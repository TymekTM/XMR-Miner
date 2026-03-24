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
