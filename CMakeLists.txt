cmake_minimum_required(VERSION 3.16)
project(XMR-Miner LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 14)

if(MSVC)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /W3 /Gd /MP")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /W3 /Gd /MP")
    set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} /O2 /Oi /Ob3 /arch:AVX2 /GL /Gw /Gy /fp:fast /favor:AMD64 /GS- /EHs-c- /GR-")
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /O2 /Oi /Ob3 /arch:AVX2 /GL /Gw /Gy /fp:fast /favor:AMD64 /GS- /EHs-c- /GR-")
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
    src/crypto/randomx/superscalar_jit.c
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
    src/crypto/randomx/superscalar_jit.c
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
    tests/test_full_jit.c
    tests/debug_jit_crash.c
)

set(RANDOMX_SOURCES
    src/crypto/randomx/reciprocal.c
    src/crypto/randomx/aes_hash.c
    src/crypto/randomx/dataset.c
    src/crypto/randomx/dataset_cache.c
    src/crypto/randomx/superscalar.c
    src/crypto/randomx/superscalar_jit.c
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
    ${RANDOMX_SOURCES}
    src/common/log.c
    src/common/cpu.c
)
target_include_directories(test_jit_loop PRIVATE src)
target_link_libraries(test_jit_loop ws2_32)

# Superscalar JIT diagnostic test
add_executable(test_ss_jit tests/test_ss_jit.c
    src/crypto/blake2/blake2b.c
    src/crypto/blake2/blake2_generator.c
    src/crypto/aes/aes_ni.c
    src/crypto/argon2/argon2.c
    src/crypto/keccak/keccak.c
    ${RANDOMX_SOURCES}
    src/common/log.c
    src/common/cpu.c
)
target_include_directories(test_ss_jit PRIVATE src)
target_link_libraries(test_ss_jit ws2_32)

add_executable(bench_aes tests/bench_aes.c
    src/crypto/randomx/aes_hash.c
    src/crypto/aes/aes_ni.c
    src/common/cpu.c
    src/common/log.c
)
target_include_directories(bench_aes PRIVATE src)

add_executable(bench_fast tests/bench_fast.c
    src/crypto/blake2/blake2b.c
    src/crypto/blake2/blake2_generator.c
    src/crypto/aes/aes_ni.c
    src/crypto/argon2/argon2.c
    src/crypto/keccak/keccak.c
    ${RANDOMX_SOURCES}
    src/common/log.c
    src/common/cpu.c
)
target_include_directories(bench_fast PRIVATE src)
target_link_libraries(bench_fast ws2_32)

# JIT smoke test (no dependencies)
add_executable(test_jit_smoke tests/test_jit_smoke.c)
target_include_directories(test_jit_smoke PRIVATE src)
target_link_libraries(test_jit_smoke ws2_32)

# JIT crash isolation test
add_executable(test_jit_crash2 tests/test_jit_crash2.c
    src/crypto/blake2/blake2b.c
    src/crypto/blake2/blake2_generator.c
    src/crypto/aes/aes_ni.c
    src/crypto/argon2/argon2.c
    src/crypto/keccak/keccak.c
    ${RANDOMX_SOURCES}
    src/common/log.c
    src/common/cpu.c
)
target_include_directories(test_jit_crash2 PRIVATE src)
target_link_libraries(test_jit_crash2 ws2_32)

# JIT dump test
add_executable(test_jit_dump tests/test_jit_dump.c
    src/crypto/blake2/blake2b.c
    src/crypto/blake2/blake2_generator.c
    src/crypto/aes/aes_ni.c
    src/crypto/argon2/argon2.c
    src/crypto/keccak/keccak.c
    ${RANDOMX_SOURCES}
    src/common/log.c
    src/common/cpu.c
)
target_include_directories(test_jit_dump PRIVATE src)
target_link_libraries(test_jit_dump ws2_32)

add_executable(test_dataset_bench tests/test_dataset_bench.c
    src/crypto/blake2/blake2b.c
    src/crypto/blake2/blake2_generator.c
    src/crypto/aes/aes_ni.c
    src/crypto/argon2/argon2.c
    src/crypto/keccak/keccak.c
    ${RANDOMX_SOURCES}
    src/common/log.c
    src/common/cpu.c
)
target_include_directories(test_dataset_bench PRIVATE src)
target_link_libraries(test_dataset_bench ws2_32)
set_target_properties(bench_fast PROPERTIES LINK_FLAGS_RELEASE "/LTCG /OPT:ICF /OPT:REF")
add_executable(test_interp_only test_interp_only.c
    src/crypto/blake2/blake2b.c src/crypto/blake2/blake2_generator.c src/crypto/aes/aes_ni.c src/crypto/argon2/argon2.c src/crypto/keccak/keccak.c ${RANDOMX_SOURCES} src/common/log.c src/common/cpu.c)
target_include_directories(test_interp_only PRIVATE src)
target_link_libraries(test_interp_only ws2_32)

add_executable(bench_profile tests/bench_profile.c
    src/crypto/blake2/blake2b.c src/crypto/blake2/blake2_generator.c src/crypto/aes/aes_ni.c src/crypto/argon2/argon2.c src/crypto/keccak/keccak.c ${RANDOMX_SOURCES} src/common/log.c src/common/cpu.c)
target_include_directories(bench_profile PRIVATE src)
target_link_libraries(bench_profile ws2_32)
add_executable(bench_mt tests/bench_mt.c src/crypto/blake2/blake2b.c src/crypto/blake2/blake2_generator.c src/crypto/aes/aes_ni.c src/crypto/argon2/argon2.c src/crypto/keccak/keccak.c ${RANDOMX_SOURCES} src/common/log.c src/common/cpu.c)
target_include_directories(bench_mt PRIVATE src)
target_link_libraries(bench_mt ws2_32)
add_executable(test_jit_only tests/test_jit_only.c src/crypto/blake2/blake2b.c src/crypto/blake2/blake2_generator.c src/crypto/aes/aes_ni.c src/crypto/argon2/argon2.c src/crypto/keccak/keccak.c ${RANDOMX_SOURCES} src/common/log.c src/common/cpu.c)
target_include_directories(test_jit_only PRIVATE src)
target_link_libraries(test_jit_only ws2_32)
add_executable(test_hash_next_multi tests/test_hash_next_multi.c src/crypto/blake2/blake2b.c src/crypto/blake2/blake2_generator.c src/crypto/aes/aes_ni.c src/crypto/argon2/argon2.c src/crypto/keccak/keccak.c ${RANDOMX_SOURCES} src/common/log.c src/common/cpu.c)
target_include_directories(test_hash_next_multi PRIVATE src)
target_link_libraries(test_hash_next_multi ws2_32)
add_executable(test_calc_hash tests/test_calc_hash.c src/crypto/blake2/blake2b.c src/crypto/blake2/blake2_generator.c src/crypto/aes/aes_ni.c src/crypto/argon2/argon2.c src/crypto/keccak/keccak.c ${RANDOMX_SOURCES} src/common/log.c src/common/cpu.c)
target_include_directories(test_calc_hash PRIVATE src)
target_link_libraries(test_calc_hash ws2_32)
