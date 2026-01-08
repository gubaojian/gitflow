## cmake version
cmake_minimum_required(VERSION 3.30.0)

set(CMAKE_BUILD_TYPE Debug)

##set(CMAKE_BUILD_TYPE Release)

# specify the C++ standard
set(CMAKE_CXX_STANDARD 20)

set(CMAKE_C_FLAGS "-DLIBUS_USE_OPENSSL")
set(CMAKE_CXX_FLAGS "-DLIBUS_USE_OPENSSL")


## project name
project(hwss)

enable_testing()
# add third party library
add_subdirectory(third_party)
include_directories(src)
include_directories(${gtest_build_include_dirs})

include_directories(${CMAKE_SOURCE_DIR}/third_party/googletest-1.15.2/googletest/include)

include_directories(${CMAKE_SOURCE_DIR}/third_party/zlib-1.2.12)

include_directories(${CMAKE_SOURCE_DIR}/third_party/uWebSockets/src/)  

include_directories(${CMAKE_SOURCE_DIR}/third_party/uWebSockets/uSockets/src)  

message("${CMAKE_SOURCE_DIR}/third_party/uWebSockets/src/")

include_directories(${CMAKE_SOURCE_DIR}/third_party/libuuid-1.0.3/)  

include_directories(${CMAKE_SOURCE_DIR}/third_party/yyjson-master/src)  


get_property(dirs DIRECTORY ${CMAKE_SOURCE_DIR} PROPERTY INCLUDE_DIRECTORIES)
message(">>> include_dirs=${dirs}") #打印一下目录情况

set(CMAKE_FIND_LIBRARY_SUFFIXES .a ${CMAKE_FIND_LIBRARY_SUFFIXES})


#find_library(ZSTD_LIB zstd ${CMAKE_SOURCE_DIR}/third_party/zstd-1.5.2)

find_library(UUID_STATIC_LIB uuid ${CMAKE_SOURCE_DIR}/third_party/libuuid-1.0.3/.libs/)

find_library(ZLIB_LIB z ${CMAKE_SOURCE_DIR}/third_party/zlib-1.2.12/)

find_library(BORINGSSL_crypto_STATIC_LIB crypto ${CMAKE_SOURCE_DIR}/third_party/uWebSockets/uSockets/boringssl/build/crypto)

find_library(BORINGSSL_ssl_STATIC_LIB ssl ${CMAKE_SOURCE_DIR}/third_party/uWebSockets/uSockets/boringssl/build/ssl)



message("uuid ${UUID_STATIC_LIB} found ${ZLIB_LIB}  ")


if(NOT EXISTS ${UUID_STATIC_LIB})
   message(FATAL_ERROR "uuid static library not found, please run build_deps.sh")
else()
   message("find uuid static ${UUID_STATIC_LIB}")
endif()



##find_library(ROCKSDB_LIB rocksdb /Users/efurture/code/lionio/lionio/third_party/rocksdb-7.1.2/librocksdb.a)
## /rocksdb-7.1.2/

##set(HWSS_SOURCES
##  src/storage/file_storage.cc  
##  src/storage/rocksdb_storage.cc
##  src/storage/storage.cc)


## add_executable(
##   hello_test
 ##  test/hello_test.cc
## )

## target_link_libraries(
##   hello_test
##   gtest_main
## )


add_subdirectory(test)


## executable 
add_executable(hwss  src/hwss.cc)


target_link_libraries(
  hwss
  ${UUID_STATIC_LIB}
  ${ZLIB_LIB}
  ${BORINGSSL_crypto_STATIC_LIB}
  ${BORINGSSL_ssl_STATIC_LIB}
  ${CMAKE_SOURCE_DIR}/third_party/uWebSockets/uSockets/uSockets.a
  yyjson
)


##target_link_libraries(
##  uuid_test
##  gtest_main
##  ${UUID_STATIC_LIB}
##)

