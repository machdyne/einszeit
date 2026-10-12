# SEC-HW-003: fail the build if the firmware image would not fit its
# partition (and so could reach the key partition).
file(SIZE ${BIN} sz)
if(sz GREATER_EQUAL ${LIMIT})
    message(FATAL_ERROR "firmware is ${sz} bytes; must stay below ${LIMIT} (firmware partition)")
endif()
message(STATUS "firmware ${sz} bytes, within the ${LIMIT}-byte firmware partition")
