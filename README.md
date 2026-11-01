<div align="center">

# XMR-Miner

### A from-scratch Monero (RandomX) miner in C, with a hand-rolled x86-64 JIT — built to find out how far an AI agent can squeeze an architecture that was already optimized by experts.

`v0.2.0` · Windows x64 · MSVC · RandomX `rx/0`

![Language](https://img.shields.io/badge/language-C%20%2F%20C%2B%2B-00599C?logo=c)
![Platform](https://img.shields.io/badge/platform-Windows%20x64-0078D4?logo=windows)
![Target](https://img.shields.io/badge/algorithm-RandomX%20rx%2F0-FF6600)
![JIT](https://img.shields.io/badge/JIT-x86--64%20runtime--generated-success)
![Status](https://img.shields.io/badge/status-research%20%2F%20experiment-blueviolet)

</div>

---

## Headline results

All numbers measured on the same **Intel Core i7-14700KF** (8 P + 12 E cores / 28 threads, 33 MB L3, DDR4-3600), 2 MB large pages, hardware AES-NI, AVX2 Argon2, batch `hash_first` / `hash_next` API, `WinRing0` MSR tuning. Every run passes the bundled **17/17 correctness checks** (JIT vs interpreter vs reference).

### Verified head-to-head — this repo vs the official RandomX reference

Synthetic benchmark, identical hardware, identical feature flags (mine mode, JIT, large pages, HW AES, AVX2, batch). The only material difference is that XMR-Miner pins worker affinity to physical P-cores.

| Threads | XMR-Miner (this repo) | Upstream RandomX v2.0.1 | Delta |
|--------:|----------------------:|------------------------:|------:|
| 1       | ~857 H/s              | 876 H/s                 | ≈ parity (both at the hardware wall) |
| 8       | **5929 H/s**          | 5176 H/s                | **+14.5 %** |

### Multi-thread scaling & sustained throughput

| Threads | Batch H/s | H/s / thread | Notes |
|--------:|----------:|-------------:|-------|
| 1       | 857       | 857          | single-thread peak ~869 H/s |
| 2       | 1714      | 857          | |
| 4       | 3302      | 826          | ~96 % of single-thread — near-linear on P-cores |
| 8       | 5929      | 741          | all 8 P-cores |
| 16      | ~6360–7000| ~400–440     | sustained 7007 H/s over a full 1 MH run |

### Versus XMRig 6.26.0 (real pool, same CPU)

| Configuration | XMRig 6.26.0 (real pool) | XMR-Miner (synthetic) |
|---|---|---|
| 1 thread, 60 s avg | ~540 H/s | ~857 H/s |
| Full CPU (28 T vs 16 T) | ~6650 H/s (peak 6848) | ~7007 H/s @ 16 T (1 MH sustained) |

> ℹ️ XMRig numbers are **real pool mining** (network + job-switch overhead); XMR-Miner numbers are **synthetic batch benchmarks**. They are not strictly like-for-like. The fairest like-for-like comparison is the head-to-head table above vs upstream RandomX.

### Phase 6: multi-lane JIT (Linux port, Xeon VM)

A second experiment ported the core to Linux and attacked the latency wall
directly: one JIT loop now interleaves the programs of 2-4 independent
hashes per thread ("software SMT"). Paired A/B on a 4-vCPU Emerald Rapids VM,
same process and dataset:

| Threads | Original path | 3-lane JIT | Gain |
|--------:|--------------:|-----------:|-----:|
| 1       | 290 H/s       | 459 H/s    | **+56 %** |
| 4       | 1233 H/s      | 1838 H/s   | **+52 %** |

Details, rejected experiments and the cost breakdown are in
[`OPTIMIZATION_LOG.md`](OPTIMIZATION_LOG.md#phase-6--linux-port--multi-lane-software-smt-jit).
The miner uses it via `--lanes` (default auto). Note: these numbers come from
a VM with ~3.2 GHz cores; they are not comparable with the 14700K tables above.

---

## What this is

A complete, single-binary Monero CPU miner, written from scratch in C/C++ with no mining dependencies:

- **Custom RandomX implementation** — blake2b, Argon2, Keccak, AES-NI, dataset / superscalar / VM, all handwritten under `src/crypto/`.
- **Runtime x86-64 JIT compiler** (`jit_compiler_x86.cpp`) that emits a fresh code block per RandomX program — prologue, loop body, epilogue — with superscalar hash code cached across recompilations.
- **Stratum JSON-RPC 2.0** client with TLS (Windows SChannel), gradual reconnect backoff, pipelined `hash_next` and deferred commitment (`pool_utils`).
- **System integration** — huge pages via `SELockMemoryPrivilege`, `VirtualLock` on scratchpad, dataset disk cache for fast restart, MSR power-limit / energy / prefetch control via `WinRing0`, per-thread QoS and affinity.
- **Test & benchmark harness** — 25 test/bench targets under `tests/`, integrated with CTest, including an upstream-RandomX adapter for A/B comparison.

It mines real Monero shares against real pools. But the project itself is not a product — it is an **experiment**.

---

## The Experiment: how far can an AI push an already-optimized architecture?

RandomX is the hard case for AI-driven optimization.

- It was **designed from the ground up** to map efficiently onto commodity CPUs and to resist ASIC acceleration. Its trade-offs were not discovered by chance — they were chosen by domain experts.
- The reference implementation ([tevador/RandomX](https://github.com/tevador/RandomX)) and the production miner ([XMRig](https://github.com/xmrig/xmrig)) have been hand-tuned over **years** by people who understand the Intel/AMD microarchitecture at the level of decode bandwidth, DSB occupancy, and L3 latency.
- The performance ceiling is set mostly by **the silicon itself**: random dependency chains the CPU cannot parallelize, ~10–12 cycle L3 scratchpad latency, ~3 cycle `IMUL`, and the `LDMXCSR` serialization that RandomX deliberately injects once per program iteration.

In other words: by the time an AI agent shows up, the easy 90 % is gone. What remains is a regime where a good change is worth single-digit percent and a clever-but-wrong change costs you hashrate or silently breaks correctness.

This repo is a record of letting AI agents grind on exactly that regime, one commit at a time, over ~3 months.

### Methodology

- **Models.** The optimization grinding was done primarily with **GLM-5 Turbo** and **GLM-5V-Turbo** (on the order of **~2 billion tokens** consumed across the project). Later validation and harder reasoning passes were run on **GLM-5.1** and **GPT-5.5** (high reasoning).
- **Loop.** Hypothesis → implement → benchmark (`bench_full`, 17 correctness checks + 5000 hashes/thread + TSC timing breakdown) → **commit if it wins, revert if it doesn't.** Every change is bounded by a measurement.
- **The commit log is the experiment log.** 170 commits. Reverted experiments are documented in [`OPTIMIZATION_LOG.md`](OPTIMIZATION_LOG.md) alongside the wins — the failures matter as much as the successes.
- **Correctness is non-negotiable.** A `-50 %` hashrate change that produces wrong hashes is a bug, not a trade-off. The JIT is continuously checked against the interpreter and against the reference implementation.

### What the AI actually found

After ~3 months and ~2 B tokens, the honest scoreboard reads roughly:

| Layer | Outcome |
|---|---|
| **Algorithm / JIT emit** | At a single thread, the custom JIT reaches **parity with the reference RandomX JIT** (~857 vs 876 H/s). The experts' JIT was already at the wall. Gains here were real but fought for in single-digit percent and in bytes-per-program. |
| **Multi-thread orchestration** | The big win. Pinning workers to physical P-cores (HT siblings excluded) and unifying affinity logic delivered **+14.5 % at 8 threads** vs upstream on the same CPU. |
| **Batch / pipeline architecture** | The single largest architectural win was adopting the `hash_first` / `hash_next` batch API end-to-end in the mining loop (**+12 % hashrate**), plus pipelined commitment in the pool path. |
| **Build / system tuning** | `/O2 /GL /GA /fp:fast /arch:AVX2`, LTCG, huge pages, `VirtualLock`, MSR prefetch/power — each worth a few percent, stacked. |

### What the AI could not do

`OPTIMIZATION_LOG.md` is candid about the walls that were hit and confirmed to be unmovable in software:

- **`LDMXCSR` serialization** (~14 cycles, once per iteration). Cannot be skipped without full MXCSR state tracking; a confirmed-correct skip path does not exist.
- **Random dependency chains.** RandomX's read-then-write pattern defeats dead-code elimination and out-of-order parallelism. Measured **CPI ≈ 0.53**, decode efficiency ~47.5 % — the core is dependency-bound, not decode-bound.
- **CBRANCH compaction** beyond the post-patch short-jump: NOP padding turned out to help alignment more than compaction helped size (reverted).
- **IMUL_RCP pool tuning** beyond 16 entries regressed; `align = 8` crashed; `align = 64` was worse than `16`.

### So… does AI help here?

Yes, but with an honest scope. In a regime this optimized, the agent behaves like a tireless, breadth-first junior optimizer with perfect memory: it tries everything, keeps what survives the benchmark, correctly identifies the hardware wall when it hits it, and never gets bored. It did **not** find a magic instruction sequence that beats the reference JIT single-threaded. It **did** find a real +14.5 % at scale by being meticulous about affinity, batching, and build flags — the integration layer where most human miners stop paying attention.

The value is the iteration speed and the exhaustive search, not supernatural insight.

---

## Development timeline

170 commits over 6 phases, 19 Mar → 14 Jun 2026.

| Phase | Window | Theme | Headline result |
|---|---|---|---|
| **0 — Genesis** | 19 Mar | First commit. x86-64 JIT scaffold, multi-threaded dataset init, `hash_first`/`hash_next` batch API. | Interpreter baseline ~50 H/s. |
| **1 — JIT breakthrough** | 24 Mar | Hardcoded JIT prologue replaced with runtime-generated code ("BREAKTHROUGH" commit). Interpreter optimized. | Interpreter 50 → 206 H/s (**4.1×**). |
| **2 — Correctness & first light** | 28 Mar – 1 Apr | Hashes match the reference implementation. Superscalar JIT. Huge pages, thread affinity. | JIT re-enabled for `rx/0` at ~630 H/s/thread. Huge pages +20–27 %, affinity +33 %. |
| **3 — JIT micro-opt campaign** | 2 Apr – 13 Apr | The bulk of the work — hundreds of commits chipping bytes off the JIT output. VEX→REX, handler packing (64/32/16-bit writes), code-align 4096→16, CBRANCH short-jump post-patch + branchless emit, IMUL_RCP elimination, specialized `blake2b` variants, `__forceinline` on hot paths. | 865 → ~891 H/s (+3 %, hard-won). |
| **4 — Build flags & infra** | 7 Apr – 11 Jun | `/O2 /GL \GA`, LTCG, AVX2, `NDEBUG`. MSR tuning via `WinRing0`. Execution profiling (TSC). Batch API in the mining loop (+12 %). `--power-limit` + watts reporting. | Single biggest architectural win: **+12 %** from batch hash API. |
| **5 — Production hardening** | 11 Jun – 14 Jun | Stratum JSON-RPC 2.0 compliance, pipelined `hash_next` + deferred commitment, TLS (SChannel), reconnect backoff, unit tests (JSON / config / blob, 70+ checks), CTest integration, upstream-RandomX adapter for A/B. Affinity logic unified. | **+11 % H/s/thread @ 16 T**. |

The full, unfiltered record — including reverted experiments — lives in [`OPTIMIZATION_LOG.md`](OPTIMIZATION_LOG.md).

---

## Performance deep-dive

Single-thread JIT timing breakdown (from `bench_full`, Phase 3):

```
blake2b(blob):          0.121 us  ( 0.0%)
fill+init x8:          0.938 us  ( 0.1%)
JIT generate x8:      18.735 us  ( 2.9%)   <- cached superscalar code, ~2.3 us/program
blake2b(reg) x9:       1.891 us  ( 0.3%)
hash_and_fill x1:     29.717 us  ( 4.6%)
MEASURED hash_next:  646.080 us
DERIVED JIT exec:    594.678 us  (92.0%)   <- the JIT does 92% of the work
JIT exec/chain:       74.335 us           <- 8 chains per hash
```

TSC profiling (500 `hash_next` calls): avg **2.68 M cycles/hash**, stddev 0.95 M, min 2.05 M — i.e. a clean run sits at ~2.05 M cycles. Per chain: ~334 K cycles @ 3.5 GHz ≈ **95.6 µs**.

**Code-size footprint** per RandomX program (8 chains): ~2,370 B for 256 instructions (9.26 B avg), ~2,670 B total loop body — fits comfortably in the micro-op decode stream buffer (DSB). Top contributors: `CBRANCH` (21 %), `ISTORE` (11 %), integer memory ops (~12 %).

---

## Project layout

```
src/
  main.c                      entry point, stratum lifecycle, reconnect loop
  common/                     log, cpu detect, memory (huge pages), config
  crypto/
    blake2/  aes/  argon2/  keccak/      primitives, handwritten
    randomx/
      vm.c  jit_compiler_x86.cpp        the VM and the JIT
      dataset.c  superscalar*.c         dataset init + superscalar program gen
      aes_hash.c  reciprocal.c          hash paths + IMUL_RCP reciprocals
      msr.c                            WinRing0 MSR / energy / prefetch control
      upstream_adapter.cpp              wraps tevador/RandomX for A/B testing
  stratum/                    json, stratum JSON-RPC 2.0, tls (SChannel)
  miner/                      miner, worker, pool_utils, blob, affinity
tests/                        25 bench + correctness targets (CTest)
tools/                        WinRing0x64.sys, XMRig 6.26.0 for comparison
OPTIMIZATION_LOG.md           the unfiltered experiment log (wins + reverts)
```

---

## Build

Requires **CMake ≥ 3.16** and **MSVC** (Visual Studio 2022). Windows x64 only.

```powershell
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release -j
```

The upstream-RandomX comparison backend is fetched via `FetchContent` (pinned commit `1e9d4b2df63fa6edf46b06789486e23c0fcaa55a`). Disable with `-DXMR_BUILD_UPSTREAM_BACKEND=OFF`.

`WinRing0x64.sys` is copied next to the binaries automatically if present under `tools/`; it is required for MSR tuning and the `--power-limit` feature.

### Linux (RandomX core, benchmark and tests)

The pool client is still Windows-only (Winsock + SChannel), but the RandomX
core, `bench_rx` and the portable tests build with GCC or Clang:

```bash
cmake -S . -B build-linux -G Ninja -DCMAKE_BUILD_TYPE=Release
ninja -C build-linux
# huge pages: 2 MB for scratchpads, optionally 1 GB for the dataset (root)
echo 1300 | sudo tee /proc/sys/vm/nr_hugepages
./build-linux/test_randomx_conformance && ./build-linux/test_multilane
./build-linux/bench_rx -t 4 --lanes 3 --gran 64
./build-linux/bench_rx -t 4 --ab "lanes=0" "lanes=3,gran=64"   # paired A/B
```

## Run

```powershell
# pool + wallet are required
build\Release\xmr-miner.exe -o pool.hashvault.pro:3333 -u <WALLET> -t 16 --power-limit 77
```

Or via config file (`mining.conf`):

```ini
pool=pool.hashvault.pro:3333
wallet=<WALLET>
threads=16
mode=single
power_limit=77
```

```powershell
build\Release\xmr-miner.exe -c mining.conf
```

### CLI reference

| Option | Description |
|---|---|
| `-c, --config <file>` | Load config from file |
| `-o, --pool <host:port>` | Mining pool (default `supportxmr.com:3333`) |
| `-u, --user <wallet>` | Monero wallet address |
| `-p, --pass <password>` | Worker password (default `x`) |
| `-t, --threads <N>` | Mining threads (default: auto) |
| `--mode <auto\|single\|dual>` | Mining mode (default `auto`) |
| `--power-limit <W>` | Set package PL1/PL2 while mining (needs `WinRing0`) |
| `--lanes <0-4>` | Hashes interleaved per thread by the multi-lane JIT (0 = auto, 1 = off) |
| `--no-huge-pages` | Disable 2 MB huge pages |
| `--tls` | Connect to pool over TLS |
| `--tls-allow` | Skip TLS certificate validation |
| `-v, --verbose` | Verbose output |

---

## Testing

13 test suites registered with CTest, plus dedicated benchmark and profiling targets:

```powershell
ctest --test-dir build --output-on-failure
```

| Test | Checks |
|---|---|
| `randomx_conformance`, `hash_vector` | Reference-vector conformance |
| `jit_correctness`, `jit_correctness2`, `jit_csim` | JIT vs interpreter, incl. a C simulator |
| `pool_hash`, `share_validate`, `pool_pipeline`, `pool_protocol` | Stratum share format + Monero tail-64 target check |
| `json_parser`, `config_parser`, `blob_helpers`, `tls` | Infra unit tests (70+ assertions) |
| `upstream_backend` | A/B against tevador/RandomX |

The flagship harness is `bench_full`:

```powershell
# 1 thread, batch mode only (fastest correctness + perf + timing run)
build\Release\bench_full.exe 1 3
# 8 threads, batch mode
build\Release\bench_full.exe 8 3
# full sweep, all modes, up to 16 threads
build\Release\bench_full.exe 16
```

It runs the 17 correctness checks, the 5000-hashes/thread benchmark, the µs-level timing breakdown, and TSC profiling, and aborts on any correctness failure.

---

## Status

Research project and engineering experiment. Not production mining software — use [XMRig](https://github.com/xmrig/xmrig) for that. No license file is currently included; treat the source as proprietary unless otherwise stated.

Mining cryptocurrencies may be regulated, taxed, or prohibited in your jurisdiction. Do not run this against pools you do not have permission to use.

---

<div align="center">

**[OPTIMIZATION_LOG.md](OPTIMIZATION_LOG.md)** — the full experiment log, wins and reverts.

</div>
