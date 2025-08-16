//
// Created by baojian on 25-8-5.
//

#ifndef CAMEL_CONFIG_H
#define CAMEL_CONFIG_H

#include <string_view>
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

#define CHECK_SIGN_USE_CRYPTO_MEMCMP  false

#define CAMEL_EVP_KEY_CACHE_SIZE  8

namespace camel{
  namespace crypto {
    void initLibCrypto();
    void cleanupLibCrypto();
    void printOpenSSLError();

    OSSL_LIB_CTX *getOSSL_LIB_CTX();

    bool fast_cmp_equals(std::string_view now_sign, std::string_view expect_sign);

  }
}

#endif //CAMEL_CONFIG_H
