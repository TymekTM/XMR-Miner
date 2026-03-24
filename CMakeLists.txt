cmake_minimum_required(VERSION 3.16)
project(XMR-Miner LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 14)

if(MSVC)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /W3 /Gd")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /W3 /Gd")
    set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} /O2 /arch:AVX2 /GL /Gw /Gy /fp:fast")
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /O2 /arch:AVX2 /GL /Gw /Gy /fp:fast")
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS NOMINMAX WIN32_LEAN_AND_MEAN)
endif()

set(SOURCES
    src/main.c
    src/common/log.c
    src/common/cpu.c
    src/common/memory.c
    src/common/config.c
    src/crypto/blake2/blake2b.c
    src/crypto/blake2/blake2_generator.c
    src/crypto/aes/aes_ni.c
    src/crypto/argon2/argon2.c
    src/crypto/keccak/keccak.c
    src/crypto/randomx/reciprocal.c
    src/crypto/randomx/aes_hash.c
    src/crypto/randomx/dataset.c
    src/crypto/randomx/dataset_cache.c
    src/crypto/randomx/superscalar.c
    src/crypto/randomx/vm.c
    src/crypto/randomx/jit_compiler_x86.cpp
    src/stratum/json.c
    src/stratum/stratum.c
    src/miner/miner.c
    src/miner/worker.c
)

set_source_files_properties(
    src/crypto/randomx/vm.c
    src/crypto/randomx/jit_compiler_x86.cpp
    src/crypto/randomx/aes_hash.c
    src/crypto/randomx/dataset.c
    src/crypto/randomx/dataset_cache.c
    src/crypto/randomx/superscalar.c
    src/crypto/aes/aes_ni.c
    PROPERTIES COMPILE_FLAGS "/GS-"
)

add_executable(xmr-miner ${SOURCES})
target_include_directories(xmr-miner PRIVATE src)
target_link_libraries(xmr-miner ws2_32)
set_target_properties(xmr-miner PROPERTIES
    LINK_FLAGS "/LTCG /OPT:ICF /OPT:REF"
)

set(TEST_SOURCES
    tests/test_blake2.c
    tests/test_aes.c
    tests/test_argon2.c
    tests/test_randomx.c
    tests/bench_jit.c
    tests/bench_compare.c
    tests/dump_jit.c
    tests/quick_jit_test.c
    tests/verify_hash_consistency.c
    tests/debug_jit_crash.c
    tests/test_full_jit.c
)

set(RANDOMX_SOURCES
    src/crypto/randomx/reciprocal.c
    src/crypto/randomx/aes_hash.c
    src/crypto/randomx/dataset.c
    src/crypto/randomx/dataset_cache.c
    src/crypto/randomx/superscalar.c
    src/crypto/randomx/vm.c
    src/crypto/randomx/jit_compiler_x86.cpp
)

    foreach(test_src ${TEST_SOURCES})
    get_filename_component(test_name ${test_src} NAME_WE)
    add_executable(${test_name} ${test_src}
        src/crypto/blake2/blake2b.c
        src/crypto/blake2/blake2_generator.c
        src/crypto/aes/aes_ni.c
        src/crypto/argon2/argon2.c
        src/crypto/keccak/keccak.c
        ${RANDOMX_SOURCES}
        src/common/log.c
        src/common/cpu.c
    )
    target_include_directories(${test_name} PRIVATE src)
    target_link_libraries(${test_name} ws2_32)
endforeach()

# Explicitly add test_jit_loop
add_executable(test_jit_loop tests/test_jit_loop.c
    src/crypto/blake2/blake2b.c
    src/crypto/blake2/blake2_generator.c
    src/crypto/aes/aes_ni.c
    src/crypto/argon2/argon2.c
    src/crypto/keccak/keccak.c
    src/crypto/randomx/reciprocal.c
    src/crypto/randomx/aes_hash.c
    src/crypto/randomx/dataset.c
    src/crypto/randomx/dataset_cache.c
    src/crypto/randomx/superscalar.c
    src/crypto/randomx/vm.c
    src/crypto/randomx/jit_compiler_x86.cpp
    src/common/log.c
    src/common/cpu.c
)
target_include_directories(test_jit_loop PRIVATE src)
target_link_libraries(test_jit_loop ws2_32)

# Test JIT vs Interpreter
add_executable(test_jit_detailed tests/test_jit_detailed.c
    src/crypto/blake2/blake2b.c
    src/crypto/blake2/blake2_generator.c
    src/crypto/aes/aes_ni.c
    src/crypto/argon2/argon2.c
    src/crypto/keccak/keccak.c
    src/crypto/randomx/reciprocal.c
    src/crypto/randomx/aes_hash.c
    src/crypto/randomx/dataset.c
    src/crypto/randomx/dataset_cache.c
    src/crypto/randomx/superscalar.c
    src/crypto/randomx/vm.c
    src/crypto/randomx/jit_compiler_x86.cpp
    src/common/log.c
    src/common/cpu.c
)
target_include_directories(test_jit_detailed PRIVATE src)
target_link_libraries(test_jit_detailed ws2_32)

add_executable(test_minimal_jit tests/test_minimal_jit.c)
target_include_directories(test_minimal_jit PRIVATE src)
target_link_libraries(test_minimal_jit ws2_32)

add_executable(test_loop_load tests/test_loop_load.c)
target_include_directories(test_loop_load PRIVATE src)
target_link_libraries(test_loop_load ws2_32)

# Full mode JIT performance test
add_executable(test_full_jit_perf tests/test_full_jit_perf.c
    src/crypto/blake2/blake2b.c
    src/crypto/blake2/blake2_generator.c
    src/crypto/aes/aes_ni.c
    src/crypto/argon2/argon2.c
    src/crypto/keccak/keccak.c
    src/crypto/randomx/reciprocal.c
    src/crypto/randomx/aes_hash.c
    src/crypto/randomx/dataset.c
    src/crypto/randomx/dataset_cache.c
    src/crypto/randomx/superscalar.c
    src/crypto/randomx/vm.c
    src/crypto/randomx/jit_compiler_x86.cpp
    src/common/log.c
    src/common/cpu.c
)
target_include_directories(test_full_jit_perf PRIVATE src)
target_link_libraries(test_full_jit_perf ws2_32)

# Quick full JIT benchmark
add_executable(quick_full_jit_bench tests/quick_full_jit_bench.c
    src/crypto/blake2/blake2b.c
    src/crypto/blake2/blake2_generator.c
    src/crypto/aes/aes_ni.c
    src/crypto/argon2/argon2.c
    src/crypto/keccak/keccak.c
    src/crypto/randomx/reciprocal.c
    src/crypto/randomx/aes_hash.c
    src/crypto/randomx/dataset.c
    src/crypto/randomx/dataset_cache.c
    src/crypto/randomx/superscalar.c
    src/crypto/randomx/vm.c
    src/crypto/randomx/jit_compiler_x86.cpp
    src/common/log.c
    src/common/cpu.c
)
target_include_directories(quick_full_jit_bench PRIVATE src)
target_link_libraries(quick_full_jit_bench ws2_32)

# Debug JIT loop test
add_executable(debug_jit_loop tests/debug_jit_loop.c
    src/crypto/blake2/blake2b.c
    src/crypto/blake2/blake2_generator.c
    src/crypto/aes/aes_ni.c
    src/crypto/argon2/argon2.c
    src/crypto/keccak/keccak.c
    src/crypto/randomx/reciprocal.c
    src/crypto/randomx/aes_hash.c
    src/crypto/randomx/dataset.c
    src/crypto/randomx/dataset_cache.c
    src/crypto/randomx/superscalar.c
    src/crypto/randomx/vm.c
    src/crypto/randomx/jit_compiler_x86.cpp
    src/common/log.c
    src/common/cpu.c
)
target_include_directories(debug_jit_loop PRIVATE src)
target_link_libraries(debug_jit_loop ws2_32)

# Interpreter-only benchmark
add_executable(bench_interpreter_only tests/bench_interpreter_only.c
    src/crypto/blake2/blake2b.c
    src/crypto/blake2/blake2_generator.c
    src/crypto/aes/aes_ni.c
    src/crypto/argon2/argon2.c
    src/crypto/keccak/keccak.c
    src/crypto/randomx/reciprocal.c
    src/crypto/randomx/aes_hash.c
    src/crypto/randomx/dataset.c
    src/crypto/randomx/dataset_cache.c
    src/crypto/randomx/superscalar.c
    src/crypto/randomx/vm.c
    src/crypto/randomx/jit_compiler_x86.cpp
    src/common/log.c
    src/common/cpu.c
)
target_include_directories(bench_interpreter_only PRIVATE src)
target_link_libraries(bench_interpreter_only ws2_32)

# JIT vs Interpreter test
add_executable(jit_vs_interpreter tests/jit_vs_interpreter.c
    src/crypto/blake2/blake2b.c
    src/crypto/blake2/blake2_generator.c
    src/crypto/aes/aes_ni.c
    src/crypto/argon2/argon2.c
    src/crypto/keccak/keccak.c
    src/crypto/randomx/reciprocal.c
    src/crypto/randomx/aes_hash.c
    src/crypto/randomx/dataset.c
    src/crypto/randomx/dataset_cache.c
    src/crypto/randomx/superscalar.c
    src/crypto/randomx/vm.c
    src/crypto/randomx/jit_compiler_x86.cpp
    src/common/log.c
    src/common/cpu.c
)
target_include_directories(jit_vs_interpreter PRIVATE src)
target_link_libraries(jit_vs_interpreter ws2_32)
