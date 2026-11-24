# Optimization Log - XMR-Miner JIT

Target: >=910 H/s single-thread JIT batch mode
CPU: Intel 13th/14th gen (8P+12E, 20 cores)

## Baseline
- ~865 H/s (before optimization work)

## Completed Experiments

| # | Change | Result | Status |
|---|--------|--------|--------|
| 1 | Eliminate dead estimating pass in JIT gen | +29 H/s (865→893) | **COMMITTED da8712f** |
| 2 | Pack CFROUND AND+OR+MOV+LDMXCSR as uint64/uint16 writes | Neutral perf, code quality | **COMMITTED 6f0187c** |
| 3 | Reduce section alignment 64→16 bytes | +24 H/s | **COMMITTED bef6160** |
| 4 | XMRig-matched handler packing (IMULH/ISMULH/INEG/IXOR) | +10-15 H/s | **COMMITTED 0cab375** |
| 5 | Pack FADD_R/FSUB_R/FMUL_R/FSCAL_R/FSQRT_R as uint32 writes | Neutral, JIT gen -8% | **COMMITTED 106c39c** |
| 6 | Dataset prefetch at loop start | Redundant (epilogue already prefetches) | REVERTED |
| 7 | CBRANCH emit-time short jumps | Cumulative offset drift | REVERTED |
| 8 | CBRANCH post-patcher compaction | -17 H/s (NOPs help alignment) | REVERTED |
| 9 | Pool size 32 | -20 H/s regression | REVERTED |
| 10 | Align=8 | Crash | REVERTED |
| 11 | CFROUND skip LDMXCSR when rounding=0 | 100% correctness failure (can't skip without tracking MXCSR state) | REVERTED |
| 12 | CBRANCH 0x2E prefix padding | -3 H/s regression | REVERTED |

## Current Performance
- ~891-894 H/s median (range 888-897)
- JIT exec: 92.5% of hash_next time (~80µs/chain)
- JIT generate: 2.7% (~2.3µs/call, 8 calls/hash)
- CPI: ~0.52 (target ~0.4 is theoretical min)

## Key Insights
- LDMXCSR serialization can't be skipped without MXCSR state tracking
- CBRANCH NOP padding helps alignment — 0x2E prefixes are worse
- Dead code elimination not viable (RandomX read-then-write pattern)
- CBRANCH can't be shortened (imm32 always >=256, TEST mask always >=0xFF00)
- IMUL_RCP pool uses RIP-relative loads from code area (potential i-cache/d-cache split)

## Instruction Size Analysis
- Average program: 2,370 bytes for 256 instructions (9.26 bytes avg)
- Total loop body: ~2,670 bytes (fits comfortably in DSB)
- Top code size contributors:
  - CBRANCH: 500 bytes (21.1%) - always 20 bytes, 25 per program
  - ISTORE: 256 bytes (10.8%) - 16 bytes each
  - FMUL_R: 160 bytes (6.8%) - 5 bytes each, 32 per program
  - FDIV_M: 124 bytes (5.2%) - 31 bytes each, 4 per program
  - FADD_M+FSUB_M: 230 bytes (9.7%) - 23 bytes each
  - IADD_M+ISUB_M+IXOR_M: 280 bytes (11.8%) - ~15 bytes each

## Hardware Counter Results (TSC profiling)
- Avg cycles/hash_next: 2,224,021 (8 chains)
- Per chain: 278,003 cycles @ 3.5 GHz = 79.4 µs
- CPI: 0.531 (theoretical min ~0.25 for 4-wide)
- Instructions retired estimate: 278K / 0.53 ≈ 524K per chain
- Stddev: 4% (88K cycles), min 2153K, max 3452K
- Decode efficiency: 1.9 IPC out of 4.0 max = 47.5%
- **Main bottleneck: dependency chains + memory latency, NOT decode bandwidth**

## Code Layout
- RX_PROGRAM_CODE_SIZE = 8224 bytes (program body area)
- RX_SUPER_CODE_SIZE = 58400 bytes (superscalar hash code)
- RX_TOTAL_CODE_SIZE = 66752 bytes
- IMUL_RCP_POOL_OFFSET = 66624 (near end, ~65KB from program body)

## Next Experiments To Try
1. IMUL_RCP stack pool — store reciprocals at [rsp+disp8] instead of [rip+disp32]
2. Try instruction scheduling / dependency chain breaking
3. Loop unrolling (reduce dec/jnz overhead)
4. VNNI or AVX-512 for SIMD parallelism (if available)

## Conclusion
After extensive optimization, we've gone from ~865 H/s to ~891 H/s (+26 H/s = +3% improvement).
The remaining gap to 910 H/s (~2.1%) is bounded by:
- **RandomX's random dependency chains** (CPU can't parallelize dependent ops)
- **Scratchpad L3 latency** (~10-12 cycles per memory load)
- **LDMXCSR serialization** (~14 cycles, 1x per program iteration, can't skip without state tracking)
- **IMUL latency** (3 cycles for MUL, can't be reduced)

Further gains would require fundamental changes like:
- AVX-512 gather/scatter for batch memory operations
- Dual-program interleaving (running 2 programs simultaneously)
- Hardware prefetch tuning via MSR
- CPU microcode-level optimizations (not possible in software)

---

# Phase 6 — Linux port + multi-lane ("software SMT") JIT

Machine: 4 vCPU KVM guest (Firecracker), Intel Xeon family 6 model 207
(Emerald Rapids), ~3.2 GHz under load (estimated from a dependent `imul`
chain), 2 MB L2/core, 260 MB L3, 15 GB RAM, Linux 6.18, GCC 13.3 `-O2
-march=native`. Single-thread figures are ~1/3 of the 14700K numbers above
because of the lower clock and the much higher L2-miss/DRAM latency of a
mesh Xeon inside a VM.

## Methodology

- `bench_rx` (new, portable): verifies the official RandomX vector and the
  batch pipeline against the interpreter before every run.
- VM noise is +-10% between runs, so decisions use `bench_rx --ab A B`:
  both configurations run in the same process and threads, alternated
  ABBA in short slices; the median per-round B/A ratio and its IQR are
  reported. An A/A run gives median 0.00%, IQR +-2%.
- Correctness gates: `test_randomx_conformance` (243 checks),
  `test_multilane` (2138 checks: lanes 1..4, banked and spilled FP,
  7 granularities x 4 option sets, official vector, JIT and interpreter
  cross-checks), `test_pool_lanes` (48 checks of the miner pipeline).

## Key finding: the VM loop is latency bound

- 1 lane: ~670 cycles per RandomX iteration for ~560 fused uops (IPC ~0.5).
  `llvm-mca -mcpu=sapphirerapids` puts the resource bound at ~108-174
  cycles per iteration, i.e. 3/4 of the time is latency.
- The cause is structural: every iteration starts with scratchpad loads
  whose address comes from the end of the previous iteration, and the
  dataset address is known only one iteration in advance, so the
  out-of-order window cannot overlap iterations of one program.

## Multi-lane JIT (`jit_multi_x86.cpp`)

One generated loop executes the programs of K independent hashes,
interleaved in segments cut right after a CBRANCH (a RandomX branch never
jumps before the previous CBRANCH, so a taken branch stays in its segment).
Integer registers are swapped through per-lane stack slots at lane
switches; FP registers are banked (lane 0: xmm0-15 VEX, lane 1: xmm16-31
EVEX) or, without AVX-512, spilled; MXCSR is per lane.

| Experiment (4 threads unless noted) | Result | Status |
|---|---|---|
| Old dual JIT (iteration-level, full state spill) vs single, 1T | +30% (372 vs 287 H/s) | baseline for the idea |
| New 2-lane JIT vs single, 1T | +43% (409 vs 289 H/s) | **kept** |
| 2 lanes, granularity 16 / 48 / 64 vs 32 | -3.4% / +2.5% / +2.5% | **G=64 kept** |
| Lane 1 pins r0..r2 in rbx/rbp/rdi (5-reg swaps) | +0.7% | kept (harmless) |
| 3 lanes (f/e resident, a/eMask memory operands) vs 2 | +9.2% | **kept** |
| 3 lanes G=32 / G=128 vs 2 lanes G=64 | +4.9% / +8.7% | G=64 kept |
| 4 lanes (FP spilled) vs 3 lanes | +1.8% (noise) | not default |
| FP spill (AVX2 only) vs AVX-512 banks, 2 / 3 lanes | +1.1% / -1.5% | spill is a free fallback |
| Skip LDMXCSR when both lanes share the mode | +0.8% / -0.2% | rejected |
| IMUL_RCP constant pool off | +0.8% (noise) | rejected |
| Scratchpad prefetch at iteration end off | -0.3% | kept on |
| Dataset prefetch hint t0 / t1 / t2 instead of NTA | -1.4% / -3.0% / -6.7% | NTA kept |
| 1 GB dataset pages vs 2 MB/THP (3 lanes, 3 alternating runs) | ~+5% | **kept (bench default)** |
| 4 KB vs 2 MB pages (1 lane) | -15% | huge pages required |
| CPUID result cached (it traps to the hypervisor) | JIT gen 46.8 -> 21.4 us / 3 programs | **kept** |
| Encoder: one memcpy per instruction instead of per byte | 46.8 -> 44.4 us | kept |

## Where the remaining time goes (diagnostic knobs, wrong hashes on purpose)

`g_mjit_diag` removes one cost at a time; A/B gain if it were free:

| Removed cost | 1 lane | 2 lanes | 3 lanes |
|---|---|---|---|
| Scratchpad L3 region fits in L2 | +13% | +11% | +13% |
| Dataset served from cache (no DRAM) | +41% | +19% | +15% |
| No LDMXCSR | 0% | +3% | +5% |
| All three | +91% | +64% | +48% |

More lanes hide the dataset latency (+41% -> +15%) but each lane adds a
2 MB scratchpad to a 2 MB L2, so returns diminish after 3 lanes.

Non-VM work per hash at 3 lanes (~480 H/s/thread): AES hash_and_fill
66-82 us, multi-JIT generation ~57 us (7.1 us per lane-program, vs 3.2 us
for the old JIT), blake2b/program fill < 5 us: ~6% of the hash time.

## Final paired result (bench_rx --ab, same process and dataset, 1 GB pages)

| Threads | Original path (old JIT, hash_first/next) | 3-lane JIT, G=64 | Gain |
|---:|---:|---:|---:|
| 1 | 290.2 H/s | 459.2 H/s | **+56.0%** |
| 4 | 1233.2 H/s | 1837.8 H/s | **+52.5%** |

1 GB dataset pages add ~5% on top for both paths.

## Bug fixed on the way

`rx_blake2b_blob()` (used by `hash_next` for the next nonce's blob) read up
to 96 bytes past the input and ignored data past 256 bytes for blobs longer
than 128 bytes -> wrong batch hashes for long blobs. Found by
`test_randomx_conformance` (241/243 -> 243/243).

## Late experiments (3 lanes, 4 threads, A/B vs G=64)

| Change | B/A median | IQR | Verdict |
|---|---:|---|---|
| +20 NOP uops per lane switch (`diag` bit 3) | -0.7% | [-4.8%, +2.9%] | loop is not uop/decode bound: trimming switch code won't help |
| G=48 | -0.8% | - | noise |
| G=80 | -1.2% | - | noise |
| G=96 (10 rounds, then 2x16 rounds) | +4.7%, +0.5%, +4.9% | all cross 0 | not confirmed, G=64 kept |
| G=160 | +2.1% | [-0.5%, +3.8%] | noise |

Granularity is flat between 48 and 160 at 3 lanes; the remaining gap is
memory latency (dataset DRAM + scratchpad spilling out of L2), not the
instruction stream.

## Open ideas not done

- Faster multi-JIT code generation (still 2x slower than the old JIT, ~3%).
- VAES (AVX-512) `hash_and_fill`: the 4 AES lanes map onto one zmm (~1-2%).
- LDMXCSR elimination via per-rounding-mode code variants with AVX-512
  embedded rounding (<= 5%, but 512-bit uops and code size make it risky).
- Validate lane count / granularity on the 14700K (no AVX-512: spill mode;
  E-cores have 1 MB L2 per core, so they may prefer 2 lanes).

---

# Phase 7 — Intel Core i7-14700KF (Hybrid 8P+12E, AVX2 + VAES) & Real-Pool Optimization

Machine: Intel Core i7-14700KF (8 Raptor Cove P-cores w/ 2 MB L2 each + 12 Gracemont E-cores in 3x4-core clusters w/ 4 MB L2 per cluster + 33 MB shared non-inclusive L3, 20C/28T, `AVX2/BMI2/VAES/GFNI`, no AVX-512), 32 GB DDR4-3600, Windows 11 x64, MSVC 19.44, 2 MB huge pages (user-space, no Admin / no MSR mod).

## Microarchitectural Discoveries & Implemented Optimizations

1. **Gracemont (E-core) `LDMXCSR` Microcode Assist (~200 cycles) & Per-VM `RX_FLAG_CFROUND_GUARD`:**
   - Diagnostic runs (`diag=4`, no `LDMXCSR`) proved any MXCSR write (`LDMXCSR` or `VLDMXCSR`) triggers a ~200-cycle serializing assist on Gracemont E-cores, collapsing 2-lane E-core throughput by -50% (243 vs 501 H/s).
   - Added `RX_FLAG_CFROUND_GUARD` (`jit_compiler_x86.cpp`): patches `stmxcsr [rsp]` in `code_first_load` and emits `cmp eax, [rsp]; je +7` in `h_CFROUND` (plus `cfround_elim`), skipping ~25% of redundant `LDMXCSR` writes.
   - Result: **+7.74% median on E-cores** (509.6 -> 540.9 H/s on 1 E-core), -0.84% on P-cores -> enabled automatically **per-VM on E-cores only**.
2. **AVX2 Multi-Lane JIT (`jit_multi_x86.cpp`) for Raptor Cove P-Cores:**
   - **2-Lane AVX2 FP Register Banking (`fpBank2`)**: Lane 0 in `xmm0..7`, Lane 1 in `xmm8..14`, only `e[3]` swapped through stack (2 vector ops instead of 16) -> **+0.97%**.
   - **Static/Lazy `LDMXCSR` Elimination (`smart_mxcsr`)**: constant-mode zero-`LDMXCSR` loop, FP-less segment skip, CFROUND-start skip, dead CFROUND load deferral, cyclic owner tracking, `FR_HWMXCSR`-tracked guard -> **+1.53%**.
   - **BMI2 `MULX` & `RORX` (`bmi2`)**: eliminates `RAX`/`RDX` clobbers in `IMULH`/`CFROUND`/`IROR`/`IROL` -> **+1.29%**.
   - **Early Dataset & Scratchpad Prefetch Ordering (`tail_order`)** -> **+0.85%**.
   - **256-Entry Opcode LUT (`g_op_lut[256]`)** + `MJ_CODE_SIZE` bumped 128 KB -> 512 KB.
   - **Granularity `G=256`** beats `G=64` by **+8.8%** and beats phase-staggered `stagger=1, G=128` by **+8.0%** on Raptor Cove AVX2 (512-entry ROB already overlaps `Tail(0)->Head(1)` while minimizing `LDMXCSR` switches).
3. **256-bit VAES YMM (`aes_hash.c`) & L1/L2 Scratchpad Warming (`vm.c`):**
   - Full 256-bit VAES implementations of `rx_hash_aes1rx4`, `rx_fill_aes1rx4`, `rx_fill_aes4rx4`, and `rx_hash_and_fill_aes1rx4` (runtime-gated by `cpu_has_vaes()`) -> **+1.59% median**.
   - L1 (16 KB `T0`) + L2 (256 KB `T1`) scratchpad warming after `hash_and_fill` (`g_vm_warm_sp=1`) -> **+1.62%**.
4. **L2+L3 Cache-Budget Hybrid Planner & Cluster-Spread Affinity (`affinity.c`, `miner.c`):**
   - Orders CPUs **Physical-First (`P-cores -> E-cores round-robin across 4-core L2 clusters -> P-HT`)** via `EfficiencyClass`.
   - `1..4T`: `3L` multi-lane on P-cores; `5..8T`: `2L` multi-lane on P-cores (32 MB fits P-L2 + L3); `>8T` hybrid: `1L` on P-cores (16 MB stays inside private 2 MB P-L2, 0 MB L3 pressure) + `1L + RX_FLAG_CFROUND_GUARD` on cluster-spread E-cores.
5. **Real-Pool Reliability, Responsiveness & Opus 5.5 Correctness Audit Fixes:**
   - Fixed `h_CFROUND` guard leakage into `generateProgramDualInterleaved` / `Light` / `SingleIter` (C1/M2).
   - Fixed `stagger=1` + `smart_mxcsr=0` switch-in MXCSR skip bug caught by expanded `test_multilane` (`opt=7`).
   - Added safe pause gate (`pause_req`/`paused_count`) in `miner_reinit_cache` and `miner_recreate_vms` (H1/M1), lock-safe `job.algo` copy, `TCP_NODELAY=1`, every-iteration job polling, and Intel-only `0x1A4` all-CPU MSR save/restore.
   - Switched both mining workers and dataset-init threads (`logical - 2`) to `THREAD_PRIORITY_IDLE` (fixing desktop/Discord freezes previously caused by `THREAD_PRIORITY_ABOVE_NORMAL` during dataset init).
   - Added Windows `VirtualAlloc2` 1 GB huge-page attempt with clean 2 MB -> 4 KB fallback.

## Live Real-Pool Comparison vs XMRig 6.26.0 (`pool.hashvault.pro:3333`, TLS, 2 MB Huge Pages, No Admin, IDLE Priority)

| Config (i7-14700KF) | XMRig 6.26.0 (live) | XMR-Miner (live) | Gain vs XMRig |
|---|---:|---:|---:|
| 1 P-core (`1T`, CPU 0) | 793.6 H/s (max 798.5) | **1,061.5 H/s** (`3L`, max 1,066.7) | **+33.8%** |
| 8 P-cores (`8T`, no HT) | 5,752.3 H/s (max 5,788.8) | **6,438.0 H/s** (`2L`, max 6,479.0) | **+11.9%** (+21.1% vs XMRig Auto on 8 cores) |
| 16 physical (`16T`, `8P+8E` cluster-spread) | 6,746.3 H/s | **7,800.3 H/s** (max 7,892.8) | **+15.6%** (+46.7% vs XMRig Auto) |
| 20 physical (`20T`, `8P+12E` auto) | 6,744.2 H/s (max 6,973.5) | **7,520.7 H/s** live / **8,189 H/s** `bench_rx` | **+11.5% live / +21.4% peak** |
| Out-of-the-box Default | 5,317.3 H/s (28T = 56 MB) | **7,521–7,800 H/s** (16T–20T) | **+41.4% to +46.7%** (+ 0% fee vs 1%) |

- **Verification**: `14/14` CTest suites pass (`test_multilane`: **7,650/7,650 checks, 0 failures**, including VAES, `RX_FLAG_CFROUND_GUARD` single/batch/dual vs interpreter, `opt=0..7`); **12/12 real HashVault shares accepted** (0 rejected, 0 stale).

---

# Phase 8 — User-Space RAPL Power Telemetry (Windows EMI v2) & H/s/W Efficiency Frontier

## Breakthrough: User-Space Intel RAPL via Windows EMI v2
- Windows exposes Intel RAPL (`RAPL_Package0_PKG`, `RAPL_Package0_PP0`) natively through `GUID_DEVICE_ENERGY_METER` (`IOCTL_EMI_GET_MEASUREMENT`, 64-bit picowatt-hours) with **zero Administrator privileges and no WinRing0 driver**.
- Integrated into `src/crypto/randomx/msr.c` as an automatic fallback in `msr_read_package_energy()`, plus 1s pre-mining baseline sampling in `miner.c` so `[PERF]` reports both **Total H/W** and **Incremental `H/dW`** above desktop background load.

## Measured H/s/W Pareto Frontier (i7-14700KF, Windows High Performance plan, active desktop ~120–138 W background, bracketed BG before/after)

| Configuration | H/s | BG (W) | PKG (W) | Delta dW | Total H/W | Incremental H/dW | Free P-cores |
|---|---:|---:|---:|---:|---:|---:|---:|
| XMRig 6.26.0 Auto (28T) | 5,193 | 138.6 W | 177.8 W | +39.3 W | 29.20 H/W | 132.3 H/dW | 0 |
| XMRig 6.26.0 16T (`8P+8E`) | 7,076 | 122.6 W | 183.9 W | +61.2 W | 38.49 H/W | 115.6 H/dW | 0 |
| XMR-Miner `16T` (`8P+8E`) | **7,858** | 119.8 W | 181.3 W | +61.5 W | **43.35 H/W** | 127.8 H/dW | 0 |
| XMR-Miner `--efficiency -t 18` (`12E+6P`) | **7,730** | 128.2 W | 178.4 W | +50.2 W | **43.33 H/W** | **154.0 H/dW** | 2 P-cores |
| XMR-Miner `--efficiency -t 16` (`12E+4P`) | 6,771–7,015 | 136.9 W | 175.5 W | +38.6 W | 38.6–41.0 H/W | **175.4 H/dW** | 4 P-cores |
| XMR-Miner `8P(2L)` (`-t 8`) | 6,135 | 136.3 W | 161.6 W | +25.3 W | 37.97 H/W | **242.6 H/dW** | 0 (12E free) |
| XMR-Miner `--efficiency` Auto (`12E ONLY`) | **4,979** | 133.7 W | **147.1 W** | **+13.3 W** | 33.85 H/W | **373.3 H/dW** | **8 P-cores** |

## Rejected / Neutral Experiments (12-round multi-core ABBA)
- Classic JIT `j_mulx`, `j_rorx`, `j_torder`, `j_sppf=1` individually on 12E (`-1.2%` to `-1.9%`); reverted `g_jit_tail_order`.
- Mixed `4P(2L)+12E` (`6,549 H/s`, `34.65 H/W`) and `6P(2L)+8E` (`5,887 H/s`, `33.75 H/W`): any multi-lane P-core running alongside E-cores spills into L3 and hurts both H/s and H/s/W. Keep P-cores at `1L` whenever E-cores are active.
- `6E x 2L @ G=256` (`1,675 H/s`): Gracemont E-cores still strongly prefer `1L + RX_FLAG_CFROUND_GUARD`.
- Windows `EcoQoS` (`ThreadPowerThrottling`): mostly ignored under High Performance; added as opt-in `--eco` for Balanced plan users.

## Post-BIOS & Windows Tuning (`Oszczedny (bez turbo)`, ~30-35 W BG) + Windows 11 Thread Director Fix
- **Key Discovery (`miner.c`)**: `THREAD_PRIORITY_IDLE` (priority 1) caused Windows 11 Intel Thread Director to aggressively throttle P-cores (-10% to -19% on P-cores while E-cores ran full speed). Switching to `BELOW_NORMAL_PRIORITY_CLASS + THREAD_PRIORITY_LOWEST` (priority 4 — still 4 levels below desktop/Discord apps) recovered **+753 H/s on 18T (+12.6%)**, **+853 H/s on 8T (+19.0%)**, and **+799 H/s on 20T (+12.6%)** with zero desktop stutter.
- Also enabled automatic 1 GB huge-page attempt in `miner.c` (`rx_alloc_dataset(2)` -> 2 MB fallback), added `g_vm_warm_sp` to classic `rx_calculate_hash_next`, lockless `stratum_get_job_generation`, and 16-hash counter flush in `worker.c`.

### Fresh Live Pool Comparison vs XMRig 6.26.0 (`pool.hashvault.pro:3333`, TLS, `Oszczedny (bez turbo)`, ~30-34 W BG)

| Config (i7-14700KF) | XMRig 6.26.0 (1% fee) | XMR-Miner (0% fee) | Gain (H/s / Total H/W) |
|---|---:|---:|---:|
| `1T` (1 P-core, `3L`) | 622 H/s @ 34.5 W | **657 H/s** (`bench_rx`: 689 H/s) @ 40.4 W | **+5.5% live / +10.8% bench** |
| `8T` (8 P-cores, `2L`) | 4,693 H/s @ 59.8 W (`78.5 H/W`) | **5,337 H/s** @ 66.7 W (**80.1 H/W**) | **+13.7% H/s / +2.1% H/W** |
| `12E` (`--efficiency` Auto) | 4,063 H/s @ 58.0 W (`70.1 H/W`, `165.5 H/dW`) | **4,351 H/s** @ 57.6 W (**75.5 H/W**, **183.0 H/dW**) | **+7.1% H/s / +7.7% H/W / +10.6% H/dW** |
| `18T` (`--efficiency`: `12E+6P`) | 6,241 H/s @ 72.3 W (`86.3 H/W`) | **6,741 H/s** @ 72.0 W (**93.6 H/W**; `bench_rx`: **109.3 H/W**) | **+8.0% H/s / +8.4% H/W** (2 P-cores free!) |
| `20T` (Auto: `8P+12E`) vs XMRig Auto `28T` | 5,459 H/s @ 72.6 W (`75.2 H/W`) | **7,144 H/s** @ 75.6 W (**94.5 H/W**) | **+30.9% H/s / +25.7% H/W** |

---

# Phase 9 — Gracemont E-Core Microarchitecture & Hybrid 20T Efficiency Push (`101.55 H/W` Live, `160+ H/dW`)

## Key Discoveries & Implemented Optimizations
1. **128-bit AES-NI (`g_aes_use_vaes = 0`) + Zero-Spill Fused Hash+Fill (`g_aes_hash_fill_upstream = 1`) (`src/crypto/randomx/aes_hash.c`):**
   - 256-bit VAES (`vaesenc ymm` + 4× `vperm2i128` per 64 B) forced all 20 cores into AVX2 256-bit power/license state, bottlenecked Port 5 on `VPERM2I128`, and cracked every 256-bit op into 2×128-bit uops on all 12 Gracemont E-cores — costing **-10.3% on E-cores during 20T mining** and **+1.3 W extra PKG power**.
   - Switching default to 128-bit AES-NI (`g_aes_use_vaes = 0`) delivered **`+5.51%` median on `20T` (16-round ABBA: `7,323 -> 7,847 H/s`, IQR `[+4.75%, +10.03%]`), `+3.78%` on `8P 1L`, `+2.72%` on `12E`**, and `-0.03%` neutral on `8P 2L`.
   - Enabling `g_aes_hash_fill_upstream = 1` (12 live XMM regs vs 20 spilling to stack in the 128 B loop + 4 KB software prefetch) added **`+1.02%` on `8P`** and **`+0.71%` on `20T`**.
2. **Gracemont & Hybrid JIT Microarchitecture Wins (`src/crypto/randomx/jit_compiler_x86.cpp`, `src/common/cpu.c`):**
   - **`g_jit_iswap_mov = 1`**: Replaces microcoded `XCHG r64, r64` (5-cycle throughput + ≥4-cycle decode stall on Gracemont) with 3× zero-latency mov-eliminated `MOV` via scratch `RAX` -> **`+1.62%` on `8P`**, **`+1.01%` on `12E`**.
   - **`g_jit_bmi2_mulx = 1` (runtime-gated by cached `cpu_has_bmi2()`)**: Replaces 1-operand `MUL` with flag-free BMI2 `MULX` in `h_IMULH_R`/`h_IMULH_M` -> **`+1.88%` on `12E`**, **`+0.21%` on `8P`**.
   - **`g_jit_inline_rcp_pool = 1`**: Places the 128-byte `IMUL_RCP` constant pool inline inside the first 4 KB JIT code page (and resets `activeRcpPoolOffset`/`activeStackRcpPool` in secondary generators `Light`/`SingleIter`/`DualInterleaved`) -> **`+1.61%` on `12E`**, neutral on `8P`.
   - **Per-VM E-core `h_IADD_RS` (`shift == 0`)**: Emits 3-byte `ADD` (all 4 ALU ports, avoids 3-cycle slow 3-component `LEA` on `r13`) when `activeCfroundGuard` is set (E-cores only) -> **`+0.80%` on `12E`** without touching P-cores.
   - **Combined 16-round ABBA (`20T`, `MAIN` vs Phase 9)**: **`+6.63%` median (`IQR [+4.42%, +8.24%]`)**.
3. **Evaluated & Rejected:**
   - **CFROUND-Aware Cross-Core P/E Chain Routing (`--pe-route`)**: Bit-exact (`32/32` vs interpreter) and achieved predicted routing (`E-cores: 66.8% cf=0, 0.2% cf>=2`; `P-cores: 0.2% cf=0, 58.2% cf>=2`), but migrating 2 MB scratchpads across non-inclusive L3/P-L2/E-L2 cost `-23%` H/s (`7,419 -> 5,654 H/s`).
   - **Full VEX-128 FP loop (`j_vex=2`)**: `-20.08%` on `20T` (reverted/removed).
   - **Global `j_sppf=2/3` (`PREFETCHT1/T2`)**: Hurt `8P` by `-2.78%` (`j_sppf=3`: `-7.47%` on `20T`).
   - **`j_cfrorx=1` (`RORX` in `h_CFROUND`)**: `-2.08%` on `12E`.

## Live Real-Pool Verification (`pool.hashvault.pro:3333`, TLS, No Admin, `Oszczedny (bez turbo)`, ~25–27 W BG)

| Config (i7-14700KF) | XMRig 6.26.0 (live) | XMR-Miner PR #3 | XMR-Miner Phase 9 | Gain vs XMRig / PR #3 |
|---|---:|---:|---:|---:|
| `12E` (`--efficiency -t 0`, 8 P-cores free) | 4,316–4,367 H/s | 4,351 H/s @ 57.6 W (`75.5 H/W`) | **4,566.9 H/s @ 54.5 W (`83.83 H/W`, `155.4 H/dW`)** | **+4.6–5.8% vs XMRig / +11.0% H/W vs PR #3** |
| `20T` (Auto `-t 0`: `8P+12E`) | 7,155–7,170 H/s (tuned) / 5,459 (auto) | 7,144 H/s @ 75.6 W (`94.5 H/W`) | **7,508.7 H/s @ 73.9 W (`101.55 H/W`, `160.4 H/dW`)** | **+4.7% tuned / +37.5% auto / +7.5% H/W vs PR #3** |

- **Verification**: **14/14 CTest suites passed (100%)**, live HashVault TLS shares accepted with 0 rejected.

---

# Phase 9.5 — `PREFETCHT0` Dataset, `17T` Hybrid Auto (`8P+9E`), Pointer-Cursor JIT, `g_jit_loop_nop=0` (`105.41 H/W` Live)

## Key Discoveries & Implemented Optimizations
1. **`g_jit_ds_prefetch_hint = 1` (`PREFETCHT0` on RandomX Dataset instead of `PREFETCHNTA`, `src/crypto/randomx/jit_compiler_x86.cpp`):**
   - `PREFETCHNTA` drops dataset cache lines from L2 upon eviction from Gracemont's small 32 KB L1D. Switching to `PREFETCHT0` keeps dataset lines resident across L1/L2 without hurting P-cores.
   - Measured **`+3.02%` median on `20T` (IQR `[+0.95%, +4.68%]`)** and **`+7.0%` H/W** in paired steady-state RAPL benchmarks.
2. **Hybrid Auto Thread Selection (`-t 0` → `17T = 8P + 9E [3/3/3]` on 8P+12E, `src/main.c`):**
   - Both our paired steady-state sweep (`14T..20T`) and GLM-5.4's Gracemont cluster-bandwidth audit proved that running 4 E-cores per 4 MB L2 cluster (`12E` alongside `8P`) overflows the cluster L2 on AES scratchpad passes (`4.45 -> 18.6 -> 26.0` cyc/64B at 2/3/4 threads/cluster) AND saturates DDR4-3600 + starves OS threads.
   - On hybrid CPUs with `pc > 0 && ec >= 8`, auto `-t 0` now selects `pc + (ec * 3) / 4` (`17T = 8P + 9E`, 3 per E-cluster, leaving 3 E-cores completely free for Windows/apps).
   - Paired steady-state sweep (`j_dspf=1`): **`17T: 7,204.6 H/s @ 73.7 W = 97.77 H/W (191.5 H/dW)`** vs `20T: 7,001.7 H/s @ 74.8 W = 93.87 H/W (143.1 H/dW)` (**+2.9% H/s, -1.1 W, +4.15% Total H/W**); `bench_rx` peak on quiet system: **`8,001.9 H/s`**.
3. **Production Default `g_jit_loop_nop = 0` (`src/crypto/randomx/jit_compiler_x86.cpp`):**
   - Caught by GLM-5.4's microarchitecture audit: `jit_compiler_x86.cpp` still defaulted to `g_jit_loop_nop = 1` (inserting a dead `NOP` at loop entry), whereas `bench_rx` had been setting `0`.
   - Paired ABBA verification: **`+1.75%` median on `12E` (`4,549.6 -> 4,629.4 H/s`, IQR `[+0.67%, +2.77%]`)** and **`+0.98%` median on `8P 1L`**.
4. **JIT & VM Efficiency Improvements (from Opus 5.5 audit):**
   - **Fast pointer-cursor JIT emitter (`src/crypto/randomx/jit_compiler_x86.cpp`)**: Replaced byte-by-byte `emitByte()` / `this->pos` aliasing store-forwarding chain with register-cached `uint8_t* p = code + pos` + `put32`/`put64`/`genAddressRegP`/`genAddressRegDstP` + single `pos` writeback across prologue, epilogue, and all instruction handlers (100% byte-identical machine code).
   - **32-bit `rr2/rr3` epilogue (`src/crypto/randomx/jit_compiler_x86.cpp`)**: Emits `41 8B C0+r2; 41 33 C0+r3` (32-bit zero-extending into `rax`) + `xor rbp, rax`, dropping `mov ecx, eax` (saves 1 uop + 2 bytes per iteration on 100% of iterations across `generateProgram`, `generateProgramSingleIter`, and both VMs in `generateProgramDualInterleaved`).
   - **Trimmed V1 `rx_fill_aes4rx4` (`src/crypto/randomx/vm.c`)**: Trims `rx_fill_aes4rx4` from `sizeof(rx_program)` (3,200 B, V2) to `RX_PROGRAM_V1_BYTES` (2,176 B) for V1 chains in `rx_vm_run_n`, `rx_vm_run_dual`, and `group_run` (-32% AES4R program-fill work per chain).
   - **Multi-lane 3×`MOV` `ISWAP_R` (`src/crypto/randomx/jit_multi_x86.cpp`)**: Ported `mov(RAX, rd); mov(rd, rs); mov(rs, RAX)` replacing microcoded `xchg(rd, rs)` (`8P 2L` now `5,231 H/s` in `bench_rx`).
5. **Evaluated & Rejected:**
   - `xorpd xmm12, xmm12` before / `cvtdq2pd xmm12, xmm12` after `ldmxcsr` (`j_cffence=1/2/3`): single-core alignment gain did not survive multi-thread load (`-3.01%` on `12E`, `-0.48%` on `9E`; reverted).
   - Early dataset prefetch inside program body (`-1.74%`), E-core-only `PREFETCHT1` (`-3.95%`), disabling `g_vm_warm_sp` (`-3.47%` on `17T`), `PREFETCHT0` in multi-lane `8P 2L` (higher variance, lower mean).

## Live Real-Pool Verification (`pool.hashvault.pro:3333`, TLS, No Admin, `Oszczedny (bez turbo)`, 55 s back-to-back)

| Config (i7-14700KF) | Steady-State H/s | PKG Power | Total H/W | Delta H/dW | vs XMRig 17T / 20T / Auto |
|---|---:|---:|---:|---:|---:|
| **XMR-Miner Phase 9.5 Auto (`-t 0` → `17T: 8P+9E [3/3/3]`)** | **7,688.4 H/s** | **72.9 W** | **105.41 H/W** | **170.5 H/dW** | **+5.2% / +9.3% / +40.8%** |
| XMRig 6.26.0 `17T` Tuned (`0x7775555`) | 7,307.6 H/s | ~73 W | ~100 H/W | — | baseline 17T |
| XMR-Miner Phase 9.5 `20T` (`-t 20: 8P+12E`) | 7,113.4 H/s | 75.9 W | 93.7 H/W | 173.7 H/dW | -2.7% / +1.1% / +30.3% |
| XMRig 6.26.0 `20T` Tuned (`0xFFF5555`) | 7,036.3 H/s | ~75.5 W | ~93 H/W | — | baseline 20T |
| **XMR-Miner Phase 9.5 Eco (`--efficiency -t 0` → `12E`)** | **4,617.5 H/s** | **55.4 W** | **83.60 H/W** | **134.7 H/dW** | **+6.9% vs XMRig 12E (`4,316`)** |
| XMRig 6.26.0 Auto (`28T` default) | 5,459.0 H/s | ~78 W | ~70 H/W | — | baseline Auto |

- **Verification**: **14/14 CTest suites passed (100%)**, live HashVault TLS shares accepted across `17T Auto`, `20T`, and `12E` with **0 rejected**.
