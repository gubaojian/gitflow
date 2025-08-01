cmake_minimum_required(VERSION 3.22.1)
project(crossbuild)

set(CMAKE_CXX_STANDARD 20)



set(JAVA_HOME_PATH $ENV{JAVA_HOME})

MESSAGE("JAVA_HOME_PATH ${JAVA_HOME_PATH}")



include_directories(${JAVA_HOME_PATH}/include/)
include_directories(${JAVA_HOME_PATH}/include/win32/)
include_directories(${JAVA_HOME_PATH}/include/linux/)
include_directories(${JAVA_HOME_PATH}/include/darwin/)

add_executable(crossbuild main.cpp
        common/Encrypt.cpp
        common/Encrypt.h)


set(ENCRYPT_SOURCE
    common/Encrypt.cpp
    common/Encrypt.h

)

set(JNI_SOURCE
    jni/EncryptJni.cpp
    jni/EncryptJni.h
    jni/org_efurture_encrypt_Encrypt.h
)

add_library(encrypt SHARED
  ${ENCRYPT_SOURCE}
  ${JNI_SOURCE}
)

