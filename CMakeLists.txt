cmake_minimum_required(VERSION 3.16)
project(XMR-Miner LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 14)
enable_testing()

option(XMR_BUILD_UPSTREAM_BACKEND
    "Build the optimized miner backend using pinned upstream RandomX" ON)

if(XMR_BUILD_UPSTREAM_BACKEND)
    include(FetchContent)
    FetchContent_Declare(randomx_upstream
        GIT_REPOSITORY https://github.com/tevador/RandomX.git
        GIT_TAG 1e9d4b2df63fa6edf46b06789486e23c0fcaa55a
        GIT_SHALLOW FALSE
    )
    FetchContent_MakeAvailable(randomx_upstream)
    set(UPSTREAM_RANDOMX_DIR "${randomx_upstream_SOURCE_DIR}")
endif()

if(MSVC)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /W3 /Gd /MP")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /W3 /Gd /MP")
    set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} /O2 /Oi /Ob3 /arch:AVX2 /GL /fp:fast /favor:INTEL64 /GS- /GR- /GA")
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /O2 /Oi /Ob3 /arch:AVX2 /GL /fp:fast /favor:INTEL64 /GS- /GR- /GA")
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS NOMINMAX WIN32_LEAN_AND_MEAN NDEBUG)
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
    src/crypto/randomx/msr.c
    src/stratum/json.c
    src/stratum/stratum.c
    src/miner/miner.c
    src/miner/pool_utils.c
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
    LINK_FLAGS "/LTCG /OPT:REF"
)

if(XMR_BUILD_UPSTREAM_BACKEND AND TARGET randomx)
    set(UPSTREAM_MINER_SOURCES
        src/main.c
        src/common/log.c
        src/common/cpu.c
        src/common/memory.c
        src/common/config.c
        src/crypto/keccak/keccak.c
        src/crypto/randomx/upstream_adapter.cpp
        src/crypto/randomx/msr.c
        src/stratum/json.c
        src/stratum/stratum.c
        src/miner/miner.c
        src/miner/pool_utils.c
        src/miner/worker.c
    )
    add_executable(xmr-miner-upstream ${UPSTREAM_MINER_SOURCES})
    target_include_directories(xmr-miner-upstream PRIVATE
        src
        "${UPSTREAM_RANDOMX_DIR}/src"
    )
    target_link_libraries(xmr-miner-upstream
        ws2_32
        randomx
    )
    set_target_properties(xmr-miner-upstream PROPERTIES
        LINK_FLAGS "/LTCG /OPT:REF"
    )

    add_executable(test_upstream_backend
        tests/test_upstream_backend.c
        src/crypto/randomx/upstream_adapter.cpp
    )
    target_include_directories(test_upstream_backend PRIVATE
        src
        "${UPSTREAM_RANDOMX_DIR}/src"
    )
    target_link_libraries(test_upstream_backend
        randomx
    )
    set_target_properties(test_upstream_backend PROPERTIES
        LINK_FLAGS "/LTCG /OPT:REF"
    )

    add_executable(bench_mt_scaling_upstream
        tests/bench_mt_scaling.c
        src/crypto/randomx/upstream_adapter.cpp
        src/crypto/randomx/msr.c
        src/common/log.c
    )
    target_include_directories(bench_mt_scaling_upstream PRIVATE
        src
        "${UPSTREAM_RANDOMX_DIR}/src"
    )
    target_link_libraries(bench_mt_scaling_upstream
        ws2_32
        randomx
    )
    set_target_properties(bench_mt_scaling_upstream PROPERTIES
        LINK_FLAGS "/LTCG /OPT:REF"
    )
endif()

set(RANDOMX_SOURCES
    src/crypto/randomx/reciprocal.c
    src/crypto/randomx/aes_hash.c
    src/crypto/randomx/dataset.c
    src/crypto/randomx/dataset_cache.c
    src/crypto/randomx/superscalar.c
    src/crypto/randomx/superscalar_jit.c
    src/crypto/randomx/vm.c
    src/crypto/randomx/jit_compiler_x86.cpp
    src/crypto/randomx/msr.c
)

set(COMMON_LIBS
    src/crypto/blake2/blake2b.c
    src/crypto/blake2/blake2_generator.c
    src/crypto/aes/aes_ni.c
    src/crypto/argon2/argon2.c
    src/crypto/keccak/keccak.c
    ${RANDOMX_SOURCES}
    src/common/log.c
    src/common/cpu.c
)

macro(add_bench_target NAME SRC EXTRA_LIBS)
    add_executable(${NAME} ${SRC} ${COMMON_LIBS})
    target_include_directories(${NAME} PRIVATE src)
    target_link_libraries(${NAME} ws2_32 ${EXTRA_LIBS})
    set_target_properties(${NAME} PROPERTIES LINK_FLAGS "/LTCG /OPT:ICF /OPT:REF")
endmacro()

add_bench_target(test_hash_vector tests/test_hash_vector.c "")
add_bench_target(test_randomx_conformance tests/test_randomx_conformance.c "")
add_bench_target(analyze_randomx_programs tests/analyze_randomx_programs.c "")
add_bench_target(profile_randomx_execution tests/profile_randomx_execution.c "")
target_compile_definitions(profile_randomx_execution PRIVATE RX_EXECUTION_PROFILE=1)
add_bench_target(bench_jit_branch_encoding tests/bench_jit_branch_encoding.c "")
add_bench_target(bench_jit_loop_nop tests/bench_jit_loop_nop.c "")
add_bench_target(bench_three_modes tests/bench_three_modes.c "")
add_bench_target(bench_unified tests/bench_unified.c "")
add_bench_target(bench_mt_scaling tests/bench_mt_scaling.c "")
add_bench_target(bench_pool_sim tests/bench_pool_sim.c "")
add_bench_target(bench_jit_timing tests/bench_jit_timing.c "")
add_bench_target(test_jit_correctness tests/test_jit_correctness.c "")
add_bench_target(test_jit_debug tests/test_jit_debug.c "")
add_bench_target(test_jit_debug2 tests/test_jit_debug2.c "")
add_bench_target(test_jit_debug3 tests/test_jit_debug3.c "")
add_bench_target(test_jit_debug4 tests/test_jit_debug4.c "")
add_bench_target(test_jit_debug5 tests/test_jit_debug5.c "")
add_bench_target(test_jit_debug6 tests/test_jit_debug6.c "")
add_bench_target(test_jit_correctness2 tests/test_jit_correctness2.c "")
add_bench_target(test_share_validate tests/test_share_validate.c "")
add_bench_target(test_pool_hash tests/test_pool_hash.c "")
add_bench_target(test_pool_pipeline tests/test_pool_pipeline.c "")
target_sources(test_pool_pipeline PRIVATE src/miner/pool_utils.c)
add_bench_target(test_pool_protocol tests/test_pool_protocol.c "")
target_sources(test_pool_protocol PRIVATE src/stratum/json.c src/stratum/stratum.c)
add_bench_target(bench_full tests/bench_full.c "")
add_bench_target(test_hash_diag tests/test_hash_diag.c "")
add_bench_target(test_jit_dump tests/test_jit_dump.c "")
add_bench_target(test_jit_csim tests/test_jit_csim.c "")
add_bench_target(test_jit_debug7 tests/test_jit_debug7.c "")
add_bench_target(sysbench_telemetry tools/sysbench_telemetry.c "")
set_target_properties(sysbench_telemetry PROPERTIES MSVC_RUNTIME_LIBRARY "MultiThreaded")

add_test(NAME randomx_conformance
    COMMAND test_randomx_conformance)
add_test(NAME hash_vector
    COMMAND test_hash_vector)
add_test(NAME jit_correctness
    COMMAND test_jit_correctness)
add_test(NAME jit_correctness2
    COMMAND test_jit_correctness2)
add_test(NAME jit_csim
    COMMAND test_jit_csim)
add_test(NAME pool_hash
    COMMAND test_pool_hash)
add_test(NAME share_validate
    COMMAND test_share_validate)
add_test(NAME pool_pipeline
    COMMAND test_pool_pipeline)
add_test(NAME pool_protocol
    COMMAND test_pool_protocol)
if(XMR_BUILD_UPSTREAM_BACKEND AND TARGET test_upstream_backend)
    add_test(NAME upstream_backend
        COMMAND test_upstream_backend)
endif()

if(EXISTS "${CMAKE_SOURCE_DIR}/tools/xmrig-win64/xmrig-6.26.0/WinRing0x64.sys")
    set(MSR_TARGETS xmr-miner bench_full bench_mt_scaling)
    if(TARGET xmr-miner-upstream)
        list(APPEND MSR_TARGETS xmr-miner-upstream bench_mt_scaling_upstream)
    endif()
    foreach(TARGET_NAME ${MSR_TARGETS})
        add_custom_command(TARGET ${TARGET_NAME} POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${CMAKE_SOURCE_DIR}/tools/xmrig-win64/xmrig-6.26.0/WinRing0x64.sys"
            "$<TARGET_FILE_DIR:${TARGET_NAME}>/WinRing0x64.sys")
    endforeach()
endif()
