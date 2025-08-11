//
// Created by baojian on 25-8-5.
//

#ifndef CONFIG_H
#define CONFIG_H

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

namespace camel{
  namespace crypto {
    void initLibCrypto();
    void cleanupLibCrypto();
    void printOpenSSLError();
  }
}

#endif //CONFIG_H
