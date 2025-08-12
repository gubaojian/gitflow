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
#include "openssl/core_names.h"

namespace camel {
    namespace crypto {

        char digest_sha2_256[] = "SHA2-256";

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

        HMACSha2_256FastSigner::HMACSha2_256FastSigner(const std::string &secret) {
            this->secret = secret;
            evpMac = EVP_MAC_fetch(nullptr, "hmac", nullptr);
            if (!evpMac) {
                return;
            }
            hmacCtx = EVP_MAC_CTX_new(evpMac);
            if (!hmacCtx) {
                EVP_MAC_free(evpMac);
                evpMac = nullptr;
                return;
            }

            // 3. 配置HMAC参数：指定底层哈希算法为SHA256

        }

        HMACSha2_256FastSigner::~HMACSha2_256FastSigner() {
            if (hmacCtx) {
                EVP_MAC_CTX_free(hmacCtx);  // 释放上下文
                hmacCtx = nullptr;
            }
            if (evpMac) {
                EVP_MAC_free(evpMac);  // 释放算法实现
                evpMac = nullptr;
            }
        }

        HMACSha2_256FastSigner::HMACSha2_256FastSigner(HMACSha2_256FastSigner&& other) noexcept
        : secret(std::move(other.secret)),
        evpMac(other.evpMac),
        hmacCtx(other.hmacCtx) {
            other.evpMac = nullptr;
            other.hmacCtx = nullptr;
        }

        // 移动赋值
        HMACSha2_256FastSigner& HMACSha2_256FastSigner::operator=(HMACSha2_256FastSigner&& other) noexcept {
            if (this != &other) {
                secret = std::move(other.secret);
                if (hmacCtx) EVP_MAC_CTX_free(hmacCtx);
                if (evpMac) EVP_MAC_free(evpMac);
                evpMac = other.evpMac;
                hmacCtx = other.hmacCtx;
                other.evpMac = nullptr;
                other.hmacCtx = nullptr;
            }
            return *this;
        }



        std::string HMACSha2_256FastSigner::sign(const std::string_view &data) {
            if (!evpMac || !hmacCtx) {
                return "";
            }
            OSSL_PARAM params[2];
            params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, digest_sha2_256, sizeof(digest_sha2_256));
            params[1] = OSSL_PARAM_END;
            // 4. 初始化HMAC（传入密钥和参数）
            if (EVP_MAC_init(hmacCtx,
                            reinterpret_cast<const uint8_t*>(secret.data()),
                            secret.size(),
                            params) != 1) {
                printOpenSSLError();
                return "";
            }
            const unsigned char *in = ( const unsigned char *)data.data();
            if (EVP_MAC_update(hmacCtx, in, data.size()) != 1) {
                printOpenSSLError();
                return "";
            }
            std::string res(static_cast<size_t>(EVP_MAX_MD_SIZE), '\0');
            size_t out_len = res.size();
            size_t outsize = res.size();
            unsigned char *out = (unsigned char *)res.data();
            if (EVP_MAC_final(hmacCtx, out, &out_len, outsize) != 1) {
                printOpenSSLError();
                return "";
            }
            res.resize(out_len);
            return res;
        }

        std::string HMACSha2_256FastSigner::signToHex(const std::string_view &data) {
            return hex_encode(sign(data));
        }

        std::string HMACSha2_256FastSigner::signToBase64(const std::string_view &data) {
            return base64_encode(sign(data));
        }

        bool HMACSha2_256FastSigner::checkSign(const std::string_view &data, const std::string_view &sign_data) {
            std::string check_sign = sign(data);
            if (check_sign.empty()) {
                return false;
            }
            if (check_sign.length() != sign_data.size()) {
                return false;
            }
            return check_sign == sign_data;
        }

        bool HMACSha2_256FastSigner::checkHexSign(const std::string_view &data, const std::string_view &sign_data) {
            return checkHexSign(data, hex_decode(sign_data));
        }

        bool HMACSha2_256FastSigner::checkBase64Sign(const std::string_view &data, const std::string_view &sign_data) {
            return checkHexSign(data, base64_decode(sign_data));
        }
    }
}
