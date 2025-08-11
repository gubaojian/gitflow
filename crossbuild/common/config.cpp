//
// Created by baojian on 25-8-5.
//

#include "config.h"

#include <iostream>


namespace camel{
  namespace crypto {
    bool _hasOpenSslInit = false;

    void initLibCrypto() {
      if (!_hasOpenSslInit) {
        OpenSSL_add_all_algorithms();
        ERR_load_crypto_strings();
        _hasOpenSslInit = true;
      }
    }

    void printOpenSSLError() {
      unsigned long errCode;
      char errMsg[256];

      while ((errCode = ERR_get_error()) != 0) {
        ERR_error_string_n(errCode, errMsg, sizeof(errMsg));
        std::cerr << "OpenSSL Error: " << errMsg << std::endl;
      }
    }

    void cleanupLibCrypto() {
      if (_hasOpenSslInit) {
        EVP_cleanup();
        ERR_free_strings();
        _hasOpenSslInit = false;
      }
    }
  }
}

