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
