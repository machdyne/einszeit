# proto.cmake -- the USB protocol: frame and payload codec (shared by device
# and host) and the device-side dispatcher.
set(EZ_PROTO_DIR ${CMAKE_CURRENT_LIST_DIR})
set(EZ_PROTO_INCLUDE ${EZ_PROTO_DIR}/include)
set(EZ_PROTO_CODEC_SOURCES ${EZ_PROTO_DIR}/src/ez_proto.c)
set(EZ_PROTO_CLIENT_SOURCES ${EZ_PROTO_DIR}/src/ez_client.c)
set(EZ_PROTO_SOURCES ${EZ_PROTO_CODEC_SOURCES} ${EZ_PROTO_DIR}/src/ez_dispatch.c)
