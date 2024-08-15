cmake_minimum_required(VERSION 3.2.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
# find_package(MbedTLS REQUIRED)
# find_package(mbedtls REQUIRED)

set(LIB_NAME "kvs-embedded-c")

# compiled as C99
set(CMAKE_C_FLAGS "--std=c99 ${CMAKE_C_FLAGS}")

# compiled as c++11
set(CMAKE_CXX_FLAGS "--std=c++11 ${CMAKE_CXX_FLAGS}")

# needed for gettimeofday()
set(CMAKE_C_FLAGS "-D_XOPEN_SOURCE=600 -D_POSIX_C_SOURCE=200112L ${CMAKE_C_FLAGS}")

set(LIB_DIR ${CMAKE_CURRENT_SOURCE_DIR})
set(ZEPHYR_DIR $ENV{ZEPHYR_BASE})


add_definitions(-DCONFIG_ARM)
add_definitions(-DCONFIG_MP_MAX_NUM_CPUS=1)

# zephyr_library_import(mbedtls modules/nrf/subsys/nrf_security/src/libmbedtls.a)
# zephyr_library_link_libraries(mbedtls)


if(${USE_LLHTTP})
    message(STATUS "GUPHY Using llhttp")
    set(LIB_SRC ${LIB_SRC}
        ${LIB_DIR}/source/net/http_parser_adapter_llhttp.c
    )
    set(LINK_LIBS ${LINK_LIBS}
        llhttp
    )
else()
    message(STATUS "GUPHY Using default http parser")
    set(LIB_SRC ${LIB_SRC}
        ${LIB_DIR}/source/net/http_parser_adapter_default.c
    )
endif()

set(LIB_SRC ${LIB_SRC}
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
    ${LIB_DIR}/source/net/http_parser_adapter.h
    ${LIB_DIR}/source/net/http_helper.c
    ${LIB_DIR}/source/net/http_helper.h
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
    ${LIB_DIR}/source/net/http_parser_adapter_llhttp.c

)

set(LIB_PUB_INC
    ${LIB_DIR}/include
    ${ZEPHYR_DIR}/include/zephyr/net
    ${ZEPHYR_DIR}/include
)

set(LIB_PRV_INC
    ${LIB_DIR}/source
)

set(LINK_LIBS ${LINK_LIBS}
    parson
    aziotsharedutil
    tlsf
)


if(NOT ${USE_WEBRTC_MBEDTLS_LIB} OR NOT ${USE_ZEPHYR_MBEDTLS_LIB})
    set(LINK_LIBS ${LINK_LIBS}
        MbedTLS
        mbedcrypto
        mbedx509
    )
endif()

if(UNIX)
    set(LIB_SRC ${LIB_SRC}
        ${LIB_DIR}/port/port_linux.c
    )
endif()

message(STATUS "LIB_SRC: ${LIB_SRC}")



# zephyr_include_directories(${LIB_PUB_INC} ${ZEPHYR_BASE}/modules/crypto/mbedtls/include)
# setup static library
add_library(${LIB_NAME} STATIC ${LIB_SRC})
# set_target_properties(${LIB_NAME} PROPERTIES POSITION_INDEPENDENT_CODE 1)
target_include_directories(${LIB_NAME} PUBLIC ${LIB_PUB_INC})
target_include_directories(${LIB_NAME} PRIVATE ${LIB_PRV_INC})
if(${USE_WEBRTC_MBEDTLS_LIB})
    target_link_directories(${LIB_NAME} PUBLIC ${WEBRTC_LIB_PATH})
    target_include_directories(${LIB_NAME} PUBLIC ${WEBRTC_INC_PATH})
endif()

target_link_libraries(${LIB_NAME} PUBLIC
    zephyr_interface
    ${LINK_LIBS}
    
)
# target_link_libraries(${LIB_NAME} PUBLIC
#     zephyr
    
#     mbedtls
#     mbedcrypto
#     mbedx509
# )
# target_compile_definitions(${LIB_NAME} PUBLIC
#     -DUSE_ZEPHYR
# )
# target_link_options(${LIB_NAME} PRIVATE
#     -lmbedtls
#     -lmbedcrypto
#     -lmbedx509
# )

if(${USE_LLHTTP})
    target_link_libraries(${LIB_NAME} PRIVATE
        llhttp
    )
endif()


include(GNUInstallDirs)

install(TARGETS ${LIB_NAME}
        LIBRARY DESTINATION ${CMAKE_INSTALL_FULL_LIBDIR}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_FULL_LIBDIR}
)

install(DIRECTORY ${LIB_PUB_INC}/
        DESTINATION ${CMAKE_INSTALL_FULL_INCLUDEDIR}
)
