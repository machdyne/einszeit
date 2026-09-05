#
# fw/test/CMakeLists.txt -- Einszeit V1 hardware validation firmware
#
# EZ-SEC-001 traceability: this build deliberately produces a NON-PRODUCTION
# artifact. See docs/EZ-TEST-TRACEABILITY.md for the requirement matrix and
# docs/EZ-TEST-DEVIATIONS.md for the accepted deviations.
#
# Two ways to build:
#
#   standalone, from this directory
#       mkdir build && cd build
#       PICO_SDK_PATH=/path/to/pico-sdk cmake .. -DCMAKE_BUILD_TYPE=Release
#       make -j
#
#   as part of the project tree, from fw/CMakeLists.txt or the repo root
#       add_subdirectory(test)
#
# In the second case the parent is expected to have already called
# pico_sdk_init(); this file detects that and does not repeat it.
#
cmake_minimum_required(VERSION 3.13)

option(EZ_ENABLE_RAW_STORAGE_DUMP
       "Expose raw FRAM/SD dump commands. Violates EZ-SEC-001 SEC-FW-004 and SEC-UI-005: only enable against a board that has never held key material."
       OFF)

# ---------------------------------------------------------------------------
# Standalone bootstrap. Skipped when a parent project already set the SDK up.
# ---------------------------------------------------------------------------
if(NOT TARGET pico_stdlib)
    # Einszeit V1 is RP2350A. The secure Arm build is required: the TRNG sits
    # behind ACCESSCTRL and is only reachable from secure code by default.
    set(PICO_PLATFORM rp2350-arm-s)

    # pico2 assumes 4 MB of QSPI flash. If V1 fits a different part, add a
    # board header and set PICO_BOARD to it. SEC-HW-003 requires firmware and
    # key data storage to occupy non-overlapping regions; on V1 key data lives
    # on the microSD, so this build shares no medium with key data.
    if(NOT DEFINED PICO_BOARD)
        set(PICO_BOARD pico2 CACHE STRING "Board type")
    endif()

    if(NOT DEFINED ENV{PICO_SDK_PATH} AND NOT DEFINED PICO_SDK_PATH)
        message(FATAL_ERROR
            "PICO_SDK_PATH is not set. Point it at a pico-sdk 2.x checkout:\n"
            "  PICO_SDK_PATH=/path/to/pico-sdk cmake ..")
    endif()

    include($ENV{PICO_SDK_PATH}/external/pico_sdk_import.cmake)
    project(einszeit_hwtest C CXX ASM)
    set(CMAKE_C_STANDARD 11)
    set(CMAKE_CXX_STANDARD 17)
    pico_sdk_init()
endif()

# ---------------------------------------------------------------------------
add_executable(einszeit_hwtest
    src/main.c
    src/ez_trng.c
    src/ez_fram.c
    src/ez_sd.c
    src/ez_clocks.c
    src/ez_pins.c
    src/ez_xmodem.c
    src/ez_container.c
    src/ez_guard.c      # SEC-FW-004, SEC-HW-002 enforcement
    src/ez_secure.c     # SEC-FW-002, SEC-FW-003 enforcement
)

target_include_directories(einszeit_hwtest PRIVATE include)

# SEC-FW-001 requires memory safety to be established by review for a C
# codebase. These warnings are part of that evidence and the tree is expected
# to build clean under them; see docs/EZ-TEST-TRACEABILITY.md.
target_compile_options(einszeit_hwtest PRIVATE
    -Wall -Wextra -Wno-unused-parameter
)

target_link_libraries(einszeit_hwtest
    pico_stdlib
    pico_unique_id
    hardware_spi
    hardware_adc
    hardware_clocks
    hardware_gpio
    hardware_powman
    hardware_watchdog
    hardware_xosc
)

# USB CDC only. UART stdio would contend for pins for no benefit here.
pico_enable_stdio_usb(einszeit_hwtest 1)
pico_enable_stdio_uart(einszeit_hwtest 0)

target_compile_definitions(einszeit_hwtest PRIVATE
    # %f is needed for throughput and die temperature figures
    PICO_PRINTF_SUPPORT_FLOAT=1
    # Don't discard output while the host is slow to drain the CDC buffer; a
    # silently dropped XMODEM block costs a full retransmit.
    PICO_STDIO_USB_STDOUT_TIMEOUT_US=500000
    PICO_STDIO_USB_CONNECT_WAIT_TIMEOUT_MS=0
    PICO_STDIO_USB_ENABLE_RESET_VIA_VENDOR_INTERFACE=1
    EZ_ENABLE_RAW_STORAGE_DUMP=$<BOOL:${EZ_ENABLE_RAW_STORAGE_DUMP}>
)

pico_add_extra_outputs(einszeit_hwtest)

if(EZ_ENABLE_RAW_STORAGE_DUMP)
    message(WARNING
        "EZ_ENABLE_RAW_STORAGE_DUMP is ON.\n"
        "This build exposes raw FRAM and microSD read paths, which violates\n"
        "EZ-SEC-001 SEC-FW-004 (no raw key storage read path) and SEC-UI-005\n"
        "(no OTP offsets in diagnostic output). Use it only on a board that\n"
        "has never held key material, and never distribute the binary.")
endif()

message(STATUS "einszeit_hwtest: bench validation firmware, NOT for production use")
