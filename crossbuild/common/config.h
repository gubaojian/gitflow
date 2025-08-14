//
// Created by baojian on 25-8-5.
//

#ifndef CONFIG_H
#define CONFIG_H

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#ifndef OSSL_PKEY_RSA_PAD_MODE_PKCS1
  #define OSSL_PKEY_RSA_PAD_MODE_PKCS1 "pkcs1"
#endif

#define CAMEL_KEY_FORMAT_BASE64  "base64"
#define CAMEL_KEY_FORMAT_HEX  "hex"
#define CAMEL_KEY_FORMAT_PEM  "pem"
#define CAMEL_KEY_FORMAT_DER  "der"
#define CAMEL_KEY_FORMAT_BINARY  "binary"
#define CAMEL_KEY_FORMAT_RAW  "raw"

namespace camel{
  namespace crypto {
    void initLibCrypto();
    void cleanupLibCrypto();
    void printOpenSSLError();
  }
}

#endif //CONFIG_H
