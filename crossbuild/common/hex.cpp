//
// Created by baojian on 25-8-5.
//

#include "hex.h"

#include <iostream>
#include <string>

#include <openssl/bn.h>
#include <__ostream/basic_ostream.h>

namespace camel {
    namespace crypto {
        std::string hex_encode(const std::string &input) {
            std::string result;
            BIGNUM *bn = BN_new();
            if (bn == nullptr) {
                return result;
            }
            result.reserve(input.size() * 2 + 2);
            BN_bin2bn((unsigned char*)input.data(), input.length(), bn);
            char *hex = BN_bn2hex(bn);
            if (hex != nullptr) {
                result.append(hex);
                OPENSSL_free(hex);
            }
            BN_free(bn);
            return result;
        }

        std::string hex_decode(const std::string &input) {
            return hex_decode(std::string_view(input));
        }

        std::string hex_decode(const std::string_view &input) {
            std::string result;
            BIGNUM *bn = BN_new();
            if (bn == nullptr) {
                return result;
            }
            if (BN_hex2bn(&bn, input.data()) == 0) {
                BN_free(bn);
                return result;
            }

            int expected_len = input.length()/2;
            result.resize(expected_len);
            unsigned char* out = (unsigned char*)(result.data());
            BN_bn2binpad(bn, out, expected_len);
            BN_free(bn);

            return result;
        }
    }
}

