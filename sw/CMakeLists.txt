#
# sw/CMakeLists.txt -- host software: ez (CLI) and ez-vdev (virtual device)
#
#   cmake -S sw -B build/sw && cmake --build build/sw
#
# Linux needs libudev (libudev-dev) for hidapi's hidraw backend; macOS uses
# IOKit. ez-vdev is POSIX only. A Windows build of ez follows.
#
cmake_minimum_required(VERSION 3.13)
project(einszeit_sw C)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(ROOT ${CMAKE_CURRENT_LIST_DIR}/..)
include(${ROOT}/core/core.cmake)
include(${ROOT}/proto/proto.cmake)
set(WARN -Wall -Wextra -Wshadow -Wno-missing-field-initializers)

add_library(ez_sw_core STATIC ${EZ_CORE_SOURCES} ${EZ_PROTO_SOURCES} ${EZ_PROTO_CLIENT_SOURCES} ${ROOT}/ui/src/ez_ui.c ${ROOT}/third_party/zetta/zetta.c ${ROOT}/xfer/src/ez_xmodem.c ${ROOT}/xfer/src/ez_zmodem.c ${ROOT}/xfer/src/ez_xfer.c
    ${ROOT}/ports/ezstore/ez_store0.c ${ROOT}/ports/ezstore/ez_ks_route.c ${ROOT}/ports/mirror/ez_ks_mirror.c)
target_include_directories(ez_sw_core PUBLIC ${EZ_CORE_INCLUDE} ${EZ_PROTO_INCLUDE} ${ROOT}/ports/ezstore ${ROOT}/ports/mirror ${ROOT}/ui/include ${ROOT}/third_party/zetta ${ROOT}/xfer/include)
target_compile_options(ez_sw_core PRIVATE ${WARN})

# hidapi (libusb/hidapi 0.15, BSD licence option), vendored in sw/.
add_library(hidapi STATIC hidapi.c)
target_include_directories(hidapi PUBLIC ${CMAKE_CURRENT_LIST_DIR})
# Third-party POSIX code: GNU extensions (O_CLOEXEC etc.); our own code stays strict C11.
set_target_properties(hidapi PROPERTIES C_EXTENSIONS ON)
target_compile_definitions(hidapi PRIVATE _GNU_SOURCE)
if(APPLE)
    target_link_libraries(hidapi PUBLIC "-framework IOKit" "-framework CoreFoundation" "-framework AppKit")
elseif(WIN32)
    target_link_libraries(hidapi PUBLIC setupapi)
else()
    target_link_libraries(hidapi PUBLIC udev)
endif()

add_executable(ez ez/ez.c ez/transport_vdev.c ez/transport_hid.c)
target_link_libraries(ez ez_sw_core hidapi)
target_compile_options(ez PRIVATE ${WARN})

find_package(Threads REQUIRED)
add_executable(ez-vdev vdev/vdev.c)
target_link_libraries(ez-vdev ez_sw_core Threads::Threads)
target_compile_options(ez-vdev PRIVATE ${WARN})

set_source_files_properties(${ROOT}/third_party/zetta/zetta.c PROPERTIES COMPILE_OPTIONS "-Wno-empty-body")   # vendored, unmodified: an intentional empty while body
