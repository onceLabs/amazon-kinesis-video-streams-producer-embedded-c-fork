cmake_minimum_required(VERSION 3.2.0)

set(LIB_NAME "kvs-embedded-c")

# compiled as C99
set(CMAKE_C_FLAGS "--std=c99 ${CMAKE_C_FLAGS}")

# compiled as c++11
set(CMAKE_CXX_FLAGS "--std=c++11 ${CMAKE_CXX_FLAGS}")

# needed for gettimeofday()
set(CMAKE_C_FLAGS "-D_XOPEN_SOURCE=600 -D_POSIX_C_SOURCE=200112L ${CMAKE_C_FLAGS}")

set(LIB_DIR ${CMAKE_CURRENT_SOURCE_DIR})
set(ZEPHYR_DIR /opt/nordic/ncs/v2.7.0/zephyr)
set(ZEPHYR_MODUELS_DIR /opt/nordic/ncs/v2.7.0/modules)

add_definitions(-DCONFIG_ARM)
add_definitions(-DCONFIG_MP_MAX_NUM_CPUS=1)
add_definitions(-DMBEDTLS_DEBUG_C)

set(LIB_SRC
    ${GENERATED_HEADERS_DIR}/autoconf.h
    ${LIB_DIR}/include/kvs/kvsapp.h
    ${LIB_DIR}/include/kvs/kvsapp_options.h
    ${LIB_DIR}/include/kvs/errors.h
    ${LIB_DIR}/include/kvs/iot_credential_provider.h
    ${LIB_DIR}/include/kvs/mkv_generator.h
    ${LIB_DIR}/include/kvs/nalu.h
    ${LIB_DIR}/include/kvs/pool_allocator.h
    ${LIB_DIR}/include/kvs/port.h
    ${LIB_DIR}/include/kvs/restapi.h
    ${LIB_DIR}/include/kvs/stream.h
    ${LIB_DIR}/source/app/kvsapp.c
    ${LIB_DIR}/source/codec/nalu.c
    ${LIB_DIR}/source/codec/sps_decode.c
    ${LIB_DIR}/source/codec/sps_decode.h
    ${LIB_DIR}/source/misc/json_helper.c
    ${LIB_DIR}/source/misc/json_helper.h
    ${LIB_DIR}/source/mkv/mkv_generator.c
    ${LIB_DIR}/source/net/http_helper.c
    ${LIB_DIR}/source/net/http_helper.h
    ${LIB_DIR}/source/net/http_parser_adapter.h
    ${LIB_DIR}/source/net/netio.c
    ${LIB_DIR}/source/net/netio.h
    ${LIB_DIR}/source/os/allocator.c
    ${LIB_DIR}/source/os/allocator.h
    ${LIB_DIR}/source/os/endian.h
    ${LIB_DIR}/source/os/pool_allocator.c
    ${LIB_DIR}/source/restful/aws_signer_v4.c
    ${LIB_DIR}/source/restful/aws_signer_v4.h
    ${LIB_DIR}/source/restful/iot/iot_credential_provider.c
    ${LIB_DIR}/source/restful/kvs/restapi_kvs.c
    ${LIB_DIR}/source/stream/stream.c
    ${LIB_DIR}/source/transport/sockets_zephyr.c
    ${ZEPHYR_MODUELS_DIR}/crypto/mbedtls/include/mbedtls/ctr_drbg.h
    ${ZEPHYR_MODUELS_DIR}/crypto/mbedtls/include/mbedtls/entropy.h
)

set(LIB_PUB_INC
    ${LIB_DIR}/include
    ${ZEPHYR_DIR}/include/zephyr/net
    ${ZEPHYR_DIR}/include
    ${ZEPHYR_DIR}/subsys/testsuite/ztest/include/zephyr
    ${GENERATED_HEADERS_DIR}
    ${GENERATED_HEADERS_DIR}/syscalls
    ${ZEPHYR_MODUELS_DIR}/crypto/mbedtls/include/mbedtls
)

set(LIB_PRV_INC
    ${LIB_DIR}/source
)

set(LINK_LIBS
    parson
    aziotsharedutil
    tlsf
)

if(${USE_LLHTTP})
    set(LIB_SRC ${LIB_SRC}
        ${LIB_DIR}/source/net/http_parser_adapter_llhttp.c
    )
    set(LINK_LIBS ${LINK_LIBS}
        llhttp
    )
else()
    set(LIB_SRC ${LIB_SRC}
        ${LIB_DIR}/source/net/http_parser_adapter_default.c
    )
endif()

if(NOT ${USE_WEBRTC_MBEDTLS_LIB})
    set(LINK_LIBS ${LINK_LIBS}
        mbedtls
        mbedcrypto
        mbedx509
    )
endif()

if(UNIX)
    set(LIB_SRC ${LIB_SRC}
        ${LIB_DIR}/port/port_linux.c
    )
endif()

message(STATUS "__ZEPHYR__: ${__ZEPHYR__}")

if (__ZEPHYR__ OR ZEPHYR_DIR)
    message(STATUS "Adding ZEPHYR PORT files (time + random)")
    set(LIB_SRC ${LIB_SRC}
        ${LIB_DIR}/port/port_zephyr.c
    )
endif()

message(STATUS "LIB_PUB_INC: ${LIB_PUB_INC}")
message(STATUS "ZEPHYR_BASE: ${ZEPHYR_BASE}")
# setup static library
add_library(${LIB_NAME} STATIC ${LIB_SRC})


set_target_properties(${LIB_NAME} PROPERTIES POSITION_INDEPENDENT_CODE 1)
target_include_directories(${LIB_NAME} PUBLIC ${LIB_PUB_INC})
target_include_directories(${LIB_NAME} PRIVATE ${LIB_PRV_INC})
if(${USE_WEBRTC_MBEDTLS_LIB})
    target_link_directories(${LIB_NAME} PUBLIC ${WEBRTC_LIB_PATH})
    target_include_directories(${LIB_NAME} PUBLIC ${WEBRTC_INC_PATH})
endif()

target_link_libraries(${LIB_NAME} PUBLIC
    ${LINK_LIBS}
)

target_link_libraries(${LIB_NAME} PUBLIC ${CMAKE_BINARY_DIR}/modules/nrf/subsys/nrf_security/src/libmbedtls.a)
target_link_libraries(${LIB_NAME} PUBLIC ${CMAKE_BINARY_DIR}/modules/nrf/subsys/nrf_security/src/libmbedcrypto_base.a)
target_link_libraries(${LIB_NAME} PUBLIC ${CMAKE_BINARY_DIR}/modules/nrf/subsys/nrf_security/src/libmbedcrypto.a)
target_link_libraries(${LIB_NAME} PUBLIC ${CMAKE_BINARY_DIR}/modules/nrf/subsys/nrf_security/src/libmbedx509.a)


# zephyr_library_link_libraries(mbedTLS)
# Zephyr specific
# if (NOT ${CMAKE_SYSTEM_NAME} STREQUAL "Zephyr")
target_link_libraries(${LIB_NAME} PRIVATE
  zephyr_interface
  zephyr_kernel
  zephyr_libc
  zephyr_minimal
  zephyr_posix
  zephyr_syscall
  zephyr_types
)
# endif()

include(GNUInstallDirs)

install(TARGETS ${LIB_NAME}
        LIBRARY DESTINATION ${CMAKE_INSTALL_FULL_LIBDIR}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_FULL_LIBDIR}
)

install(DIRECTORY ${LIB_PUB_INC}/
        DESTINATION ${CMAKE_INSTALL_FULL_INCLUDEDIR}
)
