cmake_minimum_required(VERSION 3.16)
project(XMR-Miner LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 14)

if(MSVC)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /W3 /O2 /arch:AVX2 /GS- /Gd")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /W3 /O2 /arch:AVX2 /GS- /Gd")
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
    src/crypto/randomx/superscalar.c
    src/crypto/randomx/vm.c
    src/stratum/json.c
    src/stratum/stratum.c
    src/miner/miner.c
    src/miner/worker.c
)

add_executable(xmr-miner ${SOURCES})
target_include_directories(xmr-miner PRIVATE src)
target_link_libraries(xmr-miner ws2_32)

set(TEST_SOURCES
    tests/test_blake2.c
    tests/test_aes.c
    tests/test_argon2.c
    tests/test_randomx.c
)

set(RANDOMX_SOURCES
    src/crypto/randomx/reciprocal.c
    src/crypto/randomx/aes_hash.c
    src/crypto/randomx/dataset.c
    src/crypto/randomx/superscalar.c
    src/crypto/randomx/vm.c
)

    foreach(test_src ${TEST_SOURCES})
    get_filename_component(test_name ${test_src} NAME_WE)
    if(test_name STREQUAL "test_randomx")
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
    else()
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
    endif()
    target_include_directories(${test_name} PRIVATE src)
    target_link_libraries(${test_name} ws2_32)
endforeach()
