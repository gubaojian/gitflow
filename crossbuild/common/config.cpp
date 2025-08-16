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

    OSSL_LIB_CTX *getOSSL_LIB_CTX() {
      return nullptr;
    }

    bool fast_cmp_equals(std::string_view now_sign, std::string_view expect_sign) {
      if (now_sign.length() != expect_sign.size()) {
        return false;
      }
      // none need use CRYPTO_memcmp, just fast compare is ok.
      if (CHECK_SIGN_USE_CRYPTO_MEMCMP) {
        return CRYPTO_memcmp(now_sign.data(), expect_sign.data(), now_sign.size()) == 0;
      }
      return std::memcmp(now_sign.data(), expect_sign.data(), now_sign.size()) == 0;
    }
  }
}

