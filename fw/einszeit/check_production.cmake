# IMPL-DRV-004: fail the build if the production image can enter the
# bootloader from software, or carries development features.
execute_process(COMMAND ${NM} ${ELF} OUTPUT_VARIABLE syms RESULT_VARIABLE rc)
if(NOT rc EQUAL 0)
    message(FATAL_ERROR "nm failed on ${ELF}")
endif()
foreach(bad reset_usb_boot rom_reset_usb_boot tr05_mode selftest_kat dev_cli dev_early)
    string(REGEX MATCH "[ \t]${bad}\n" hit "${syms}")
    if(hit)
        message(FATAL_ERROR "production image contains '${bad}' (IMPL-DRV-004 / IMPL-MODE-001)")
    endif()
endforeach()
message(STATUS "production image: no software path into the bootloader, no development features")
