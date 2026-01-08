cmake_minimum_required(VERSION 3.31)
project(CurlDemo)

set(CMAKE_CXX_STANDARD 20)

include_directories(${CMAKE_SOURCE_DIR}/libs/curllib/include)
set(CURL_LIBRARY "${CMAKE_SOURCE_DIR}/libs/curllib/lib/libcurl.a")


set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL 3.5.1 REQUIRED CONFIG
        PATHS "${CMAKE_CURRENT_SOURCE_DIR}/libs/openssl/lib/cmake/OpenSSL"
        NO_DEFAULT_PATH)

# 检查是否找到
if(OPENSSL_FOUND)
    message(STATUS "Found OpenSSL: ${OPENSSL_VERSION} (${OPENSSL_INCLUDE_DIR})")
    include_directories(${OPENSSL_INCLUDE_DIR})
else()
    message(FATAL_ERROR "OpenSSL not found. Please install OpenSSL or check the path.")
endif()


add_executable(CurlDemo main.cpp)

target_link_libraries(
        CurlDemo
        ${CURL_LIBRARY}
        OpenSSL::SSL
        OpenSSL::Crypto
        z
)
