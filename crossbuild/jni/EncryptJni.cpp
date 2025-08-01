//
// Created by baojian on 25-8-1.
//

#include "EncryptJni.h"


JNIEXPORT void JNICALL Java_org_efurture_encrypt_Encrypt_doCmd
  (JNIEnv *env, jclass jcls, jstring cmd, jstring args) {
    env->GetStringChars(cmd, JNI_FALSE);
    printf("hello world");
}