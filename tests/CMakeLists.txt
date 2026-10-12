# tests/CMakeLists.txt -- Einszeit host test suite (EZ-IMPL-001 §12.1)
#
#   cmake -S tests -B build/tests && cmake --build build/tests -j
#   ctest --test-dir build/tests --output-on-failure
#
# or simply: tests/run.sh
#
# Built with AddressSanitizer and UndefinedBehaviorSanitizer by default
# (EZ_SANITIZE=ON); part of the SEC-FW-001 evidence.
cmake_minimum_required(VERSION 3.13)
project(einszeit_host_tests C)

option(EZ_SANITIZE "Build with ASan and UBSan" ON)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

include(${CMAKE_CURRENT_LIST_DIR}/../core/core.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/../proto/proto.cmake)

set(EZ_WARN -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Werror)
set(EZ_SAN "")
if(EZ_SANITIZE)
    set(EZ_SAN -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer)
endif()

add_library(ez_core STATIC ${EZ_CORE_SOURCES})
target_include_directories(ez_core PUBLIC ${EZ_CORE_INCLUDE})
target_compile_options(ez_core PRIVATE ${EZ_WARN} ${EZ_SAN} -g -O1)
target_link_options(ez_core PUBLIC ${EZ_SAN})

# FatFs (vendored, unmodified) and the FatFs key storage port. FatFs is
# third-party code: built with sanitizers but without the core's -Werror
# warning set.
add_library(ez_fatfs STATIC
    ${CMAKE_CURRENT_LIST_DIR}/../third_party/fatfs/ff.c
    ${CMAKE_CURRENT_LIST_DIR}/../third_party/fatfs/ffunicode.c
    ${CMAKE_CURRENT_LIST_DIR}/../ports/fatfs/ez_ks_fatfs.c
)
target_include_directories(ez_fatfs PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}/../ports/fatfs
    ${CMAKE_CURRENT_LIST_DIR}/../third_party/fatfs)
target_link_libraries(ez_fatfs PUBLIC ez_core)
target_compile_options(ez_fatfs PRIVATE ${EZ_SAN} -g -O1)
set_source_files_properties(${CMAKE_CURRENT_LIST_DIR}/../ports/fatfs/ez_ks_fatfs.c
    PROPERTIES COMPILE_OPTIONS "-Wall;-Wextra;-Werror")

# The drive 0 key store and the key storage router (EZ-IMPL-001 §2.6).
add_library(ez_store0 STATIC
    ${CMAKE_CURRENT_LIST_DIR}/../ports/ezstore/ez_store0.c
    ${CMAKE_CURRENT_LIST_DIR}/../ports/ezstore/ez_ks_route.c
    ${CMAKE_CURRENT_LIST_DIR}/../ports/mirror/ez_ks_mirror.c
)
target_include_directories(ez_store0 PUBLIC ${CMAKE_CURRENT_LIST_DIR}/../ports/ezstore ${CMAKE_CURRENT_LIST_DIR}/../ports/mirror)
target_link_libraries(ez_store0 PUBLIC ez_core)
target_compile_options(ez_store0 PRIVATE ${EZ_WARN} ${EZ_SAN} -g -O1)

# The USB protocol (EZ-IMPL-001 §9): codec, dispatcher, host client.
add_library(ez_proto STATIC ${EZ_PROTO_SOURCES} ${EZ_PROTO_CLIENT_SOURCES})
target_include_directories(ez_proto PUBLIC ${EZ_PROTO_INCLUDE})
target_link_libraries(ez_proto PUBLIC ez_core)
target_compile_options(ez_proto PRIVATE ${EZ_WARN} ${EZ_SAN} -g -O1)

add_library(ez_testlib STATIC
    framework/ez_test.c
    sim/sim_fram.c
    unit/meta_fixture.c
    sim/sim_keystore.c
    sim/sim_trng.c
    sim/sim_blockdev.c
    sim/sim_flash.c
    unit/core_fixture.c
)
target_include_directories(ez_testlib PUBLIC framework sim unit)
target_link_libraries(ez_testlib PUBLIC ez_core ez_fatfs ez_store0 ez_proto)
target_compile_options(ez_testlib PRIVATE -Wall -Wextra -Wno-missing-field-initializers ${EZ_SAN} -g -O1)

enable_testing()
set(EZ_TESTS test_primitives test_meta test_meta_powercut test_meta_bitflip test_meta_rollback
             test_codec test_entropy test_core test_keygen test_engine test_media
             test_keystore test_sum test_chaos test_store0 test_proto test_mirror)
foreach(t ${EZ_TESTS})
    add_executable(${t} unit/${t}.c)
    target_link_libraries(${t} ez_testlib)
    target_compile_options(${t} PRIVATE -Wall -Wextra -Wno-missing-field-initializers ${EZ_SAN} -g -O1)
    target_compile_definitions(${t} PRIVATE _GNU_SOURCE)
    add_test(NAME ${t} COMMAND ${t})
endforeach()

# Host tool: run the device's entropy monitor and acceptance tests over a
# capture file (EZ-IMPL-001 §7.2 threshold check against real data).
add_executable(ez_entropy_check tools/ez_entropy_check.c)
target_link_libraries(ez_entropy_check ez_core)
target_compile_definitions(ez_entropy_check PRIVATE _GNU_SOURCE)
target_compile_options(ez_entropy_check PRIVATE -Wall -Wextra ${EZ_SAN} -g -O2)

# Host software under the same sanitizers, for the end-to-end test
# (tests/e2e/e2e.sh): the CLI and the virtual device.
set(SW ${CMAKE_CURRENT_LIST_DIR}/../sw)
add_library(hidapi STATIC ${SW}/hidapi.c)
target_include_directories(hidapi PUBLIC ${SW})
target_link_libraries(hidapi PUBLIC udev)
# Third-party POSIX code: GNU extensions (O_CLOEXEC etc.); our own code stays strict C11.
set_target_properties(hidapi PROPERTIES C_EXTENSIONS ON)
target_compile_definitions(hidapi PRIVATE _GNU_SOURCE)
add_executable(ez ${SW}/ez/ez.c ${SW}/ez/transport_vdev.c ${SW}/ez/transport_hid.c)
target_link_libraries(ez ez_proto ez_core hidapi ${EZ_SAN})
target_compile_options(ez PRIVATE -Wall -Wextra -Wno-missing-field-initializers ${EZ_SAN} -g -O1)
add_library(ez_ui ${CMAKE_CURRENT_LIST_DIR}/../ui/src/ez_ui.c ${CMAKE_CURRENT_LIST_DIR}/../third_party/zetta/zetta.c ${CMAKE_CURRENT_LIST_DIR}/../xfer/src/ez_xmodem.c ${CMAKE_CURRENT_LIST_DIR}/../xfer/src/ez_zmodem.c ${CMAKE_CURRENT_LIST_DIR}/../xfer/src/ez_xfer.c)
target_include_directories(ez_ui PUBLIC ${CMAKE_CURRENT_LIST_DIR}/../ui/include ${CMAKE_CURRENT_LIST_DIR}/../third_party/zetta ${CMAKE_CURRENT_LIST_DIR}/../xfer/include)
target_link_libraries(ez_ui ez_proto ez_core)
target_compile_options(ez_ui PRIVATE -Wall -Wextra -Wshadow -Werror ${EZ_SAN})
add_executable(ez-vdev ${SW}/vdev/vdev.c)
find_package(Threads REQUIRED)
target_link_libraries(ez-vdev ez_ui ez_proto ez_store0 ez_core ${EZ_SAN} Threads::Threads)
target_compile_options(ez-vdev PRIVATE -Wall -Wextra -Wno-missing-field-initializers ${EZ_SAN} -g -O1)

# Hardware simulation (tests/hwsim): the firmware's SD driver, block layer
# and card module, compiled unchanged against a pico-sdk shim and an
# emulated SD card.
set(FW ${CMAKE_CURRENT_LIST_DIR}/../fw/einszeit)
add_executable(test_sdcard hwsim/test_sdcard.c hwsim/sim_sdcard.c
    ${FW}/src/ez_sd.c ${FW}/src/hal_sdblk.c ${FW}/src/card.c)
target_include_directories(test_sdcard BEFORE PRIVATE ${CMAKE_CURRENT_LIST_DIR}/hwsim/include ${CMAKE_CURRENT_LIST_DIR}/hwsim ${FW}/include)
target_compile_definitions(test_sdcard PRIVATE EZ_DEV=1)
target_link_libraries(test_sdcard ez_testlib ${EZ_SAN})
target_compile_options(test_sdcard PRIVATE -Wall -Wextra -Wno-unused-parameter -Wno-missing-field-initializers ${EZ_SAN} -g -O1)

# File transfer protocols (xfer/): each its own module, tested on its own.
add_library(ez_xfer ${CMAKE_CURRENT_LIST_DIR}/../xfer/src/ez_xmodem.c ${CMAKE_CURRENT_LIST_DIR}/../xfer/src/ez_zmodem.c ${CMAKE_CURRENT_LIST_DIR}/../xfer/src/ez_xfer.c)
target_include_directories(ez_xfer PUBLIC ${CMAKE_CURRENT_LIST_DIR}/../xfer/include)
target_compile_options(ez_xfer PRIVATE -Wall -Wextra -Wshadow -Wconversion -Werror ${EZ_SAN})
add_executable(test_xmodem unit/test_xmodem.c)
target_link_libraries(test_xmodem ez_xfer ez_testlib ${EZ_SAN})
add_executable(test_xfer unit/test_xfer.c)
target_link_libraries(test_xfer ez_xfer ez_testlib ${EZ_SAN})
add_executable(test_zmodem unit/test_zmodem.c)
target_link_libraries(test_zmodem ez_xfer ez_testlib ${EZ_SAN})
add_executable(xf_peer xfer/xf_peer.c)
target_link_libraries(xf_peer ez_xfer ${EZ_SAN})
target_compile_options(xf_peer PRIVATE ${EZ_SAN})
add_executable(zm_peer xfer/zm_peer.c)
target_link_libraries(zm_peer ez_xfer ${EZ_SAN})
target_compile_options(zm_peer PRIVATE ${EZ_SAN})
add_executable(xm_peer xfer/xm_peer.c)
target_link_libraries(xm_peer ez_xfer ${EZ_SAN})
target_compile_options(xm_peer PRIVATE ${EZ_SAN})

set_source_files_properties(${CMAKE_CURRENT_LIST_DIR}/../third_party/zetta/zetta.c PROPERTIES COMPILE_OPTIONS "-Wno-empty-body")   # vendored, unmodified: an intentional empty while body
