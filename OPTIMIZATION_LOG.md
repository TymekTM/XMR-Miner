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

## Open ideas not done

- Faster multi-JIT code generation (still 2x slower than the old JIT, ~3%).
- VAES (AVX-512) `hash_and_fill`: the 4 AES lanes map onto one zmm (~1-2%).
- LDMXCSR elimination via per-rounding-mode code variants with AVX-512
  embedded rounding (<= 5%, but 512-bit uops and code size make it risky).
- Validate lane count / granularity on the 14700K (no AVX-512: spill mode;
  E-cores have 1 MB L2 per core, so they may prefer 2 lanes).
