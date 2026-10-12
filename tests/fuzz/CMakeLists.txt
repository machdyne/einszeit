#
# tests/fuzz -- libFuzzer harnesses for every parser of untrusted input
# Requires clang.
#
#   CC=clang cmake -S tests/fuzz -B build/fuzz && cmake --build build/fuzz
#   tests/fuzz/run.sh build/fuzz 60          # 60 seconds per fuzzer
#
cmake_minimum_required(VERSION 3.13)
project(einszeit_fuzz C)
set(CMAKE_C_STANDARD 11)
set(T ${CMAKE_CURRENT_LIST_DIR}/..)
set(ROOT ${T}/..)
include(${ROOT}/core/core.cmake)
include(${ROOT}/proto/proto.cmake)
set(FZ -fsanitize=fuzzer-no-link,address,undefined -fno-sanitize-recover=undefined -g -O1)
set(FL -fsanitize=fuzzer,address,undefined)

add_library(fz_lib STATIC ${EZ_CORE_SOURCES} ${EZ_PROTO_SOURCES}
    ${ROOT}/ports/fatfs/ez_ks_fatfs.c ${ROOT}/third_party/fatfs/ff.c ${ROOT}/third_party/fatfs/ffunicode.c
    ${ROOT}/ports/ezstore/ez_store0.c
    ${T}/sim/sim_fram.c ${T}/sim/sim_keystore.c ${T}/sim/sim_trng.c ${T}/sim/sim_blockdev.c
    ${T}/sim/sim_flash.c ${T}/framework/ez_test.c ${T}/unit/core_fixture.c ${T}/unit/meta_fixture.c)
target_include_directories(fz_lib PUBLIC ${EZ_CORE_INCLUDE} ${EZ_PROTO_INCLUDE} ${ROOT}/ports/fatfs
    ${ROOT}/ports/ezstore ${ROOT}/third_party/fatfs ${T}/sim ${T}/framework ${T}/unit)
target_compile_options(fz_lib PRIVATE ${FZ})

add_library(fz_xfer STATIC ${ROOT}/xfer/src/ez_xmodem.c ${ROOT}/xfer/src/ez_zmodem.c ${ROOT}/xfer/src/ez_xfer.c)
target_include_directories(fz_xfer PUBLIC ${ROOT}/xfer/include)
target_compile_options(fz_xfer PRIVATE ${FZ})
add_executable(fuzz_xfer fuzz_xfer.c)
target_link_libraries(fuzz_xfer fz_xfer)
target_compile_options(fuzz_xfer PRIVATE ${FZ})
target_link_options(fuzz_xfer PRIVATE ${FL})

foreach(f fuzz_dispatch fuzz_message fuzz_fatfs fuzz_store0)
    add_executable(${f} ${f}.c)
    target_link_libraries(${f} fz_lib)
    target_compile_options(${f} PRIVATE ${FZ})
    target_link_options(${f} PRIVATE ${FL})
endforeach()
