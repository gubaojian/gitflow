cmake_minimum_required(VERSION 3.22.1)
project(crossbuild)

set(CMAKE_CXX_STANDARD 20)



set(JAVA_HOME_PATH $ENV{JAVA_HOME})

MESSAGE("JAVA_HOME_PATH ${JAVA_HOME_PATH}")



include_directories(${JAVA_HOME_PATH}/include/)
include_directories(${JAVA_HOME_PATH}/include/win32/)
include_directories(${JAVA_HOME_PATH}/include/linux/)
include_directories(${JAVA_HOME_PATH}/include/darwin/)


#查找 OpenSSL，CMake 模块路径
set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL 3.5.1 REQUIRED CONFIG
        PATHS "${CMAKE_CURRENT_SOURCE_DIR}/deps/openssl/lib/cmake/OpenSSL"
        NO_DEFAULT_PATH)

# 检查是否找到
if(OPENSSL_FOUND)
    message(STATUS "Found OpenSSL: ${OPENSSL_VERSION} (${OPENSSL_INCLUDE_DIR})")
    include_directories(${OPENSSL_INCLUDE_DIR})
else()
    message(FATAL_ERROR "OpenSSL not found. Please install OpenSSL or check the path.")
endif()


add_executable(crossbuild main.cpp
        common/Encrypt.cpp
        common/Encrypt.h
        common/rsa.cpp
        common/rsa.h
        common/config.h
        common/config.cpp
        common/hex.cpp
        common/hex.h
        common/base64.cpp
        common/base64.h
        test/test_rsa.cpp
        test/test_rsa.h
        common/file_utils.h
        test/test_base64.cpp
        test/test_base64.h
        test/test_hex.cpp
        test/test_hex.h
        test/test.h
        demo/demo_rsa.cpp
        demo/demo_rsa.h
        demo/demo.h
)

target_link_libraries(crossbuild
    OpenSSL::SSL
    OpenSSL::Crypto
)


set(ENCRYPT_SOURCE
    common/Encrypt.cpp
    common/Encrypt.h

)

set(JNI_SOURCE
    jni/EncryptJni.cpp
    jni/EncryptJni.h
    jni/org_efurture_encrypt_Encrypt.h
    common/rsa.cpp
    common/rsa.h
    common/config.h
    common/hex.cpp
    common/hex.h
    common/base64.cpp
    common/base64.h
    common/file_utils.h
)

add_library(encrypt SHARED
  ${ENCRYPT_SOURCE}
  ${JNI_SOURCE}
)

