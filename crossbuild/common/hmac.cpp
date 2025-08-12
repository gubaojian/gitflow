//
// Created by baojian on 25-8-12.
//

#include "hmac.h"

#include "openssl/evp.h"
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>

#include "base64.h"
#include "config.h"
#include "hex.h"

namespace camel {
    namespace crypto {

        HMACSha2_256Signer::HMACSha2_256Signer(const std::string &secret) {
            this->secret = secret;
        }


        std::string HMACSha2_256Signer::sign(const std::string_view &data) {
            std::string res(static_cast<size_t>(EVP_MAX_MD_SIZE), '\0');
            auto len = static_cast<unsigned int>(res.size());
            if (HMAC(EVP_sha256(),
                 secret.data(),
                     static_cast<int>(secret.size()),
                     reinterpret_cast<const unsigned char*>(data.data()),
                     static_cast<int>(data.size()),
                     (unsigned char*)res.data(), // NOLINT(google-readability-casting) requires `const_cast`
                     &len) == nullptr) {
                         printOpenSSLError();
                         return "";
                     }
            res.resize(len);
            return res;
        }

        std::string HMACSha2_256Signer::signToHex(const std::string_view &data) {
            return hex_encode(sign(data));
        }

        std::string HMACSha2_256Signer::signToBase64(const std::string_view &data) {
            return base64_encode(sign(data));
        }

        bool HMACSha2_256Signer::checkSign(const std::string_view &data, const std::string_view &sign_data) {
            std::string check_sign = sign(data);
            if (check_sign.empty()) {
                return false;
            }
            if (check_sign.length() != sign_data.size()) {
                return false;
            }
            return check_sign == sign_data;
        }

        bool HMACSha2_256Signer::checkHexSign(const std::string_view &data, const std::string_view &sign_data) {
            return checkHexSign(data, hex_decode(sign_data));
        }

        bool HMACSha2_256Signer::checkBase64Sign(const std::string_view &data, const std::string_view &sign_data) {
            return checkHexSign(data, base64_decode_url_safe(sign_data));
        }

    }
}
