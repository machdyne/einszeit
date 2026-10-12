# core/core.cmake -- portable core source list (EZ-IMPL-001 §1.2).
# Included by the host test suite and (Phase 3) the RP2350 firmware.
set(EZ_CORE_DIR ${CMAKE_CURRENT_LIST_DIR})
set(EZ_CORE_INCLUDE ${EZ_CORE_DIR}/include)
set(EZ_CORE_SOURCES
    ${EZ_CORE_DIR}/src/ez_status.c
    ${EZ_CORE_DIR}/src/ez_crc.c
    ${EZ_CORE_DIR}/src/ez_secure.c
    ${EZ_CORE_DIR}/src/ez_meta.c
    ${EZ_CORE_DIR}/src/ez_msg.c
    ${EZ_CORE_DIR}/src/ez_base64.c
    ${EZ_CORE_DIR}/src/ez_entropy.c
    ${EZ_CORE_DIR}/src/ez_core.c
    ${EZ_CORE_DIR}/src/ez_engine.c
    ${EZ_CORE_DIR}/src/ez_keygen.c
    ${EZ_CORE_DIR}/src/ez_sha256.c
    ${EZ_CORE_DIR}/src/ez_sum.c
    ${EZ_CORE_DIR}/src/ez_import.c
)
