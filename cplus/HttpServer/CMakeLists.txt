cmake_minimum_required(VERSION 3.31)
project(HttpServer)

set(CMAKE_CXX_STANDARD 20)

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

add_executable(HttpServer main.cpp
        http-server.h)

target_link_libraries(HttpServer
        OpenSSL::SSL
        OpenSSL::Crypto
)
