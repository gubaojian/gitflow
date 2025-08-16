//
// Created by baojian on 25-8-12.
//

#ifndef CAMEL_HMAC_SIGN_H
#define CAMEL_HMAC_SIGN_H
#include <iostream>
#include <string>

#include "openssl/types.h"

namespace camel {
    namespace crypto {

        /***
        * # define OSSL_MAC_NAME_BLAKE2BMAC    "BLAKE2BMAC"
        * # define OSSL_MAC_NAME_BLAKE2SMAC    "BLAKE2SMAC"
        * # define OSSL_MAC_NAME_CMAC          "CMAC"
        * # define OSSL_MAC_NAME_GMAC          "GMAC"
        * # define OSSL_MAC_NAME_HMAC          "HMAC"
        * # define OSSL_MAC_NAME_KMAC128       "KMAC128"
        * # define OSSL_MAC_NAME_KMAC256       "KMAC256"
        *  # define OSSL_MAC_NAME_POLY1305      "POLY1305"
        *  # define OSSL_MAC_NAME_SIPHASH       "SIPHASH"
        *
        *  Known DIGEST names (not a complete list)
        *  # define OSSL_DIGEST_NAME_MD5            "MD5"
        *  # define OSSL_DIGEST_NAME_MD5_SHA1       "MD5-SHA1"
        *  # define OSSL_DIGEST_NAME_SHA1           "SHA1"
        *  # define OSSL_DIGEST_NAME_SHA2_224       "SHA2-224"
        *  # define OSSL_DIGEST_NAME_SHA2_256       "SHA2-256"
        *  # define OSSL_DIGEST_NAME_SHA2_256_192   "SHA2-256/192"
        *  # define OSSL_DIGEST_NAME_SHA2_384       "SHA2-384"
        *  # define OSSL_DIGEST_NAME_SHA2_512       "SHA2-512"
        *  # define OSSL_DIGEST_NAME_SHA2_512_224   "SHA2-512/224"
        *  # define OSSL_DIGEST_NAME_SHA2_512_256   "SHA2-512/256"
        *  # define OSSL_DIGEST_NAME_RIPEMD160      "RIPEMD160"
        *  # define OSSL_DIGEST_NAME_SHA3_224       "SHA3-224"
        *  # define OSSL_DIGEST_NAME_SHA3_256       "SHA3-256"
        *  # define OSSL_DIGEST_NAME_SHA3_384       "SHA3-384"
        *  # define OSSL_DIGEST_NAME_SHA3_512       "SHA3-512"
        *  # define OSSL_DIGEST_NAME_KECCAK_KMAC128 "KECCAK-KMAC-128"
        *  # define OSSL_DIGEST_NAME_KECCAK_KMAC256 "KECCAK-KMAC-256"
        *  # define OSSL_DIGEST_NAME_SM3            "SM3"
         *
         * like HMAC/SHA2-256
         * like KMAC128:myapp_v1
         * like CMAC/AES-128
         * like GMAC/AES-128-GCM
         * like BLAKE2BMAC
         * like SIPHASH
         */
        class MacSigner {
        public:
            explicit MacSigner(const std::string& algorithm, const std::string& secret);
            ~MacSigner()=default;
            std::string sign(const std::string_view& plainData);
            std::string signToHex(const std::string_view& data);
            std::string signToBase64(const std::string_view& data);
            bool checkSign(const std::string_view& data, const std::string_view& sign);
            bool checkHexSign(const std::string_view& data, const std::string_view& sign);
            bool checkBase64Sign(const std::string_view& data, const std::string_view& sign);
        public:
            void setNonce(const std::string_view& nonce) {
                if (nonce.empty() || nonce.size() != 16) {
                    std::cerr << "POLY1305 need 16 byte nonce" << std::endl;
                }
                this->nonce = nonce;
            }
            std::string getNonce() const {
                return this->nonce;
            }
        private:
            std::string algorithm;
            std::string secret;
            std::string macName;
            std::string hashName;
        private:
            std::string nonce;  // 用于POLY1305的nonce
        };

        namespace DigestUtils {
            std::string hmac_sha256(const std::string_view& data, const std::string_view& secret);
            std::string hmac_sha256ToHex(const std::string_view& data, const std::string_view& secret);
            std::string hmac_sha256ToBase64(const std::string_view& data, const std::string_view& secret);
        }


    }
}





#endif //CAMEL_HMAC_SIGN_H
