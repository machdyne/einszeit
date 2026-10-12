#
# fw/einszeit/CMakeLists.txt -- Einszeit V1 firmware (RP2350A)
#
#   mkdir build && cd build
#   PICO_SDK_PATH=/path/to/pico-sdk cmake .. -DCMAKE_BUILD_TYPE=Release
#   make -j
#
# Builds the production images einszeit_hid, einszeit_cdc and
# einszeit_composite, the development image einszeit_dev, and the
# partition table einszeit_pt (see README.md and EZ-UI-001 §11).
#
cmake_minimum_required(VERSION 3.13)

set(PICO_PLATFORM rp2350-arm-s)      # secure Arm build: TRNG behind ACCESSCTRL
if(NOT DEFINED PICO_BOARD)
    set(PICO_BOARD pico2 CACHE STRING "Board type")   # 4 MB QSPI flash, as V1
endif()
if(NOT DEFINED PICO_SDK_PATH AND DEFINED ENV{PICO_SDK_PATH})
    set(PICO_SDK_PATH $ENV{PICO_SDK_PATH} CACHE PATH "pico-sdk 2.1.1")
endif()
if(NOT DEFINED PICO_SDK_PATH)
    message(FATAL_ERROR "PICO_SDK_PATH is not set (pico-sdk 2.1.1)")
endif()
include(${PICO_SDK_PATH}/external/pico_sdk_import.cmake)
project(einszeit C CXX ASM)
set(CMAKE_C_STANDARD 11)
pico_sdk_init()

set(ROOT ${CMAKE_CURRENT_LIST_DIR}/../..)
include(${ROOT}/core/core.cmake)
include(${ROOT}/proto/proto.cmake)

# Two images (IMPL-MODE-001):
#   einszeit_dev  development: CDC debug shell + HID, `fw update`, marks the
#                 device (IMPL-MODE-002). Never for real secrets (DEV-19).
#   einszeit_hid  production: HID only, no shell, no software path into the
#                 bootloader (IMPL-DRV-004). Updates need the BOOT button.
set(EZ_FW_COMMON
    ${EZ_CORE_SOURCES} ${EZ_PROTO_SOURCES}
    ${ROOT}/ports/fatfs/ez_ks_fatfs.c ${ROOT}/third_party/fatfs/ff.c ${ROOT}/third_party/fatfs/ffunicode.c
    ${ROOT}/ports/ezstore/ez_store0.c ${ROOT}/ports/ezstore/ez_ks_route.c
    ${ROOT}/ports/mirror/ez_ks_mirror.c
    src/app.c src/card.c src/usb.c src/hal_fram.c src/hal_flash.c src/hal_sdblk.c src/hal_trng.c src/ez_sd.c)

function(einszeit_image name)
    add_executable(${name} ${ARGN})
    target_include_directories(${name} PRIVATE
        include ${EZ_CORE_INCLUDE} ${EZ_PROTO_INCLUDE} ${ROOT}/ports/fatfs ${ROOT}/ports/ezstore ${ROOT}/ports/mirror ${ROOT}/third_party/fatfs ${ROOT}/ui/include ${ROOT}/third_party/zetta ${ROOT}/xfer/include)
    target_compile_options(${name} PRIVATE -Wall -Wextra -Wno-unused-parameter)
    target_link_libraries(${name} pico_stdlib pico_unique_id pico_flash pico_bootrom pico_multicore tinyusb_device
        hardware_spi hardware_flash hardware_gpio hardware_watchdog hardware_clocks)
    pico_enable_stdio_usb(${name} 0)        # USB is driven through TinyUSB directly (usb.c)
    pico_enable_stdio_uart(${name} 0)
    target_compile_definitions(${name} PRIVATE PICO_FLASH_SIZE_BYTES=4194304)
    pico_add_extra_outputs(${name})
    # SEC-HW-003: the image must end below the drive 0 key partition.
    add_custom_command(TARGET ${name} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -DBIN=$<TARGET_FILE_DIR:${name}>/${name}.bin
                -DLIMIT=1040384 -P ${CMAKE_CURRENT_LIST_DIR}/check_size.cmake)   # 1016 KiB partition
endfunction()

# The same warnings the host suite enforces on the core apply on target.
set_source_files_properties(${EZ_CORE_SOURCES} PROPERTIES COMPILE_OPTIONS "-Wall;-Wextra;-Wshadow;-Werror")

# The images (EZ-UI-001 §11). Production: einszeit_hid (protocol only, for
# ez), einszeit_cdc (the terminal interface only), einszeit_composite (both).
# Development: einszeit_dev (both, plus the development commands).
set(EZ_UI_SOURCES ${ROOT}/ui/src/ez_ui.c ${ROOT}/third_party/zetta/zetta.c ${ROOT}/xfer/src/ez_xmodem.c ${ROOT}/xfer/src/ez_zmodem.c ${ROOT}/xfer/src/ez_xfer.c)

einszeit_image(einszeit_dev ${EZ_FW_COMMON} ${EZ_UI_SOURCES} src/main_ui.c src/shell.c src/selftest.c src/tr05.c)
target_compile_definitions(einszeit_dev PRIVATE EZ_DEV=1 EZ_BRINGUP=1 EZ_USB_CDC=1 EZ_USB_HID=1)
target_link_libraries(einszeit_dev pico_bootrom)

function(einszeit_production name cdc hid)
    if(cdc)
        einszeit_image(${name} ${EZ_FW_COMMON} ${EZ_UI_SOURCES} src/main_ui.c)
    else()
        einszeit_image(${name} ${EZ_FW_COMMON} src/main_prod.c)
    endif()
    target_compile_definitions(${name} PRIVATE EZ_PRODUCTION=1 EZ_USB_CDC=${cdc} EZ_USB_HID=${hid})
    # IMPL-DRV-004, checked on the binary: no software path into the
    # bootloader, no development features.
    add_custom_command(TARGET ${name} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -DELF=$<TARGET_FILE:${name}> -DNM=${CMAKE_NM}
                -P ${CMAKE_CURRENT_LIST_DIR}/check_production.cmake)
endfunction()
einszeit_production(einszeit_hid 0 1)
einszeit_production(einszeit_cdc 1 0)
einszeit_production(einszeit_composite 1 1)

# The flash partition table (IMPL-DRV-003, OI-02), as a UF2 to install once
# with the BOOT button before the firmware: firmware 8 KiB..1 MiB, key
# partition 1 MiB..4084 KiB with Secure-only access. Procedure: TR-06.
pico_init_picotool()
add_custom_target(einszeit_pt ALL
    COMMAND picotool partition create ${CMAKE_CURRENT_LIST_DIR}/partitions.json ${CMAKE_CURRENT_BINARY_DIR}/einszeit_pt.uf2
    DEPENDS ${CMAKE_CURRENT_LIST_DIR}/partitions.json
    COMMENT "partition table -> einszeit_pt.uf2")
