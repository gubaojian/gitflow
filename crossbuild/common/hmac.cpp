//
// Created by baojian on 25-8-12.
//

#include "hmac.h"

#include "config.h"
#include "base64.h"
#include "hex.h"

#include <iostream>
#include "openssl/evp.h"
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include "openssl/core_names.h"
#include "openssl/rand.h"


namespace camel {
    namespace crypto {

        inline bool macAlgorithmHas(const std::string& algorithm, std::string_view target) {
            return algorithm.find(target) != std::string::npos;
        }

        /**
         *  HMAC_MD5("HmacMD5"),
         * HMAC_SHA_1("HmacSHA1"),
         * HMAC_SHA_224("HmacSHA224"),
         * HMAC_SHA_256("HmacSHA256"),
         * HMAC_SHA_384("HmacSHA384"),
         * HMAC_SHA_512("HmacSHA512");
        * # define OSSL_DIGEST_NAME_MD5            "MD5"
        * # define OSSL_DIGEST_NAME_MD5_SHA1       "MD5-SHA1"
        * # define OSSL_DIGEST_NAME_SHA1           "SHA1"
        * # define OSSL_DIGEST_NAME_SHA2_224       "SHA2-224"
        * # define OSSL_DIGEST_NAME_SHA2_256       "SHA2-256"
        * # define OSSL_DIGEST_NAME_SHA2_256_192   "SHA2-256/192"
        * # define OSSL_DIGEST_NAME_SHA2_384       "SHA2-384"
        * # define OSSL_DIGEST_NAME_SHA2_512       "SHA2-512"
        * # define OSSL_DIGEST_NAME_SHA2_512_224   "SHA2-512/224"
        * # define OSSL_DIGEST_NAME_SHA2_512_256   "SHA2-512/256"
        * # define OSSL_DIGEST_NAME_MD2            "MD2"
        * # define OSSL_DIGEST_NAME_MD4            "MD4"
        * # define OSSL_DIGEST_NAME_MDC2           "MDC2"
        * # define OSSL_DIGEST_NAME_RIPEMD160      "RIPEMD160"
        * # define OSSL_DIGEST_NAME_SHA3_224       "SHA3-224"
        * # define OSSL_DIGEST_NAME_SHA3_256       "SHA3-256"
        * # define OSSL_DIGEST_NAME_SHA3_384       "SHA3-384"
        * # define OSSL_DIGEST_NAME_SHA3_512       "SHA3-512"
         * @param algorithm
         * @param target
         * @return
         */
        inline std::string getMacHashName(const std::string& algorithm) {
            if (macAlgorithmHas(algorithm, "MD5-SHA1")) {
                return "MD5-SHA1";
            }
            if (macAlgorithmHas(algorithm, "SHA2-256/192")) {
                return "SHA2-256/192";
            }
            if (macAlgorithmHas(algorithm, "SHA2-512/224")) {
                return "SHA2-512/224";
            }
            if (macAlgorithmHas(algorithm, "SHA2-512/256")) {
                return "SHA2-512/256";
            }
            if (macAlgorithmHas(algorithm, "SHA2-224")) {
                return "SHA2-224";
            }
            if (macAlgorithmHas(algorithm, "SHA2-256")) {
                return "SHA2-256";
            }
            if (macAlgorithmHas(algorithm, "SHA2-384")) {
                return "SHA2-384";
            }
            if (macAlgorithmHas(algorithm, "SHA2-512")) {
                return "SHA2-512";
            }
            if (macAlgorithmHas(algorithm, "SHA3-224")) {
                return "SHA3-224";
            }
            if (macAlgorithmHas(algorithm, "SHA3-256")) {
                return "SHA3-256";
            }
            if (macAlgorithmHas(algorithm, "SHA3-384")) {
                return "SHA3-384";
            }
            if (macAlgorithmHas(algorithm, "SHA3-512")) {
                return "SHA3-512";
            }
            if (macAlgorithmHas(algorithm, "SHA1")) {
                return "SHA1";
            }
            if (macAlgorithmHas(algorithm, "MD5")) {
                return "MD5";
            }
            if (macAlgorithmHas(algorithm, "SM3")) {
                return "SM3";
            }
            std::cerr << "find none hash, use default SHA2-256" << std::endl;
            return "SHA2-256";
        }

        /**
        * # define OSSL_MAC_NAME_BLAKE2BMAC    "BLAKE2BMAC"
        * # define OSSL_MAC_NAME_BLAKE2SMAC    "BLAKE2SMAC"
        * # define OSSL_MAC_NAME_CMAC          "CMAC"
        * # define OSSL_MAC_NAME_GMAC          "GMAC"
        * # define OSSL_MAC_NAME_HMAC          "HMAC"
        * # define OSSL_MAC_NAME_KMAC128       "KMAC128"
        * # define OSSL_MAC_NAME_KMAC256       "KMAC256"
        * # define OSSL_MAC_NAME_POLY1305      "POLY1305"
        * # define OSSL_MAC_NAME_SIPHASH       "SIPHASH"
         * @param algorithm
         * @return
         */
        inline std::string getMacName(const std::string& algorithm) {
            if (macAlgorithmHas(algorithm, "HMAC")) {
                return "HMAC";
            }
            if (macAlgorithmHas(algorithm, "BLAKE2BMAC")) {
                return "BLAKE2BMAC";
            }
            if (macAlgorithmHas(algorithm, "BLAKE2SMAC")) {
                return "BLAKE2SMAC";
            }
            if (macAlgorithmHas(algorithm, "CMAC")) {
                return "CMAC";
            }
            if (macAlgorithmHas(algorithm, "GMAC")) {
                return "GMAC";
            }
            if (macAlgorithmHas(algorithm, "KMAC128")) {
                return "KMAC128";
            }
            if (macAlgorithmHas(algorithm, "KMAC256")) {
                return "KMAC256";
            }
            if (macAlgorithmHas(algorithm, "POLY1305")) {
                return "POLY1305";
            }
            if (macAlgorithmHas(algorithm, "SIPHASH")) {
                return "SIPHASH";
            }
            return "HMAC";
        }

        inline std::string getGMacCiperName(const std::string& algorithm) {
            if (macAlgorithmHas(algorithm, "AES-256-GCM")) {
                return "AES-256-GCM";
            }
            if (macAlgorithmHas(algorithm, "AES-128-GCM")) {
                return "AES-128-GCM";
            }
            if (macAlgorithmHas(algorithm, "SM4-GCM")) {
                return "SM4-GCM";
            }
            return "AES-128-GCM";
        }

        inline std::string getCMacCiperName(const std::string& algorithm) {
            if (macAlgorithmHas(algorithm, "AES-128")) {
                return "AES-128";
            }
            if (macAlgorithmHas(algorithm, "AES-256")) {
                return "AES-256";
            }
            if (macAlgorithmHas(algorithm, "SM4")) {
                return "SM4";
            }
            if (macAlgorithmHas(algorithm, "DES-EDE3")) {
                return "DES-EDE3";
            }
            return "AES-128";
        }

        inline std::string getKMacCustom(const std::string& algorithm) {
            size_t colonPos = algorithm.find(':');
            if (colonPos != std::string::npos && colonPos < algorithm.size() - 1) {
                return algorithm.substr(colonPos + 1);
            }
            return "";  // 无自定义参数时返回空
        }

        inline bool sign_cmp_equals(std::string_view now_sign, std::string_view expect_sign) {
            if (now_sign.length() != expect_sign.size()) {
                return false;
            }
            // CRYPTO_memcmp(now_sign.data(), expect_sign.data(), now_sign.size()) == 0;
            // none need use CRYPTO_memcmp, just fast compare is ok.
            if (CHECK_SIGN_USE_CRYPTO_MEMCMP) {
                return CRYPTO_memcmp(now_sign.data(), expect_sign.data(), now_sign.size()) == 0;
            }
            return std::memcmp(now_sign.data(), expect_sign.data(), now_sign.size()) == 0;
        }
    }
}

namespace camel {
    namespace crypto {
        MacSigner::MacSigner(const std::string &algorithm, const std::string_view &secret) {
            this->algorithm = algorithm;
            this->secret = secret;
            this->macName = getMacName(algorithm);
            this->hashName = getMacHashName(algorithm);
        }


        /**
        * 原生带密钥哈希 MAC	BLAKE2SMAC、BLAKE2BMAC	不需要（内置哈希逻辑）
        * 通用哈希框架 MAC	HMAC	需要（指定底层哈希，如 SHA256）
        *  分组密码 MAC	CMAC、GMAC	不需要（依赖分组密码，如 AES）
        *  专用轻量 MAC	POLY1305、SIPHASH	不需要（自有算法逻辑）
         * @param params
         * @param macName
         * @param hashName
         */
        inline void set_mac_params_by_name( OSSL_PARAM* params,
                                             const std::string& algorithm,
                                             const std::string& macName,
                                             const std::string& hashName,
                                             const std::string& secret,
                                             std::string& nonce
                                             ) {
            if ("HMAC" == macName) {
                params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, (char*)hashName.data(), hashName.size()),
                params[1] =OSSL_PARAM_END;
                return;
            }

            if ("BLAKE2BMAC" == macName
                || "BLAKE2SMAC" == macName
                || "POLY1305" == macName
                || "SIPHASH" == macName) {
                params[0] =OSSL_PARAM_END;
                return;
            }

            if ("CMAC" == macName) {
                std::string cliperName = getCMacCiperName(algorithm);
                params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_CIPHER, (char*)cliperName.data(), cliperName.size()),
                params[1] =OSSL_PARAM_END;
                return;
                }

            if ("GMAC" == macName) {
                std::string cliperName = getGMacCiperName(algorithm);
                params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_CIPHER, (char*)cliperName.data(), cliperName.size()),
                params[1] =OSSL_PARAM_END;
                return;
            }

            if (macName == "POLY1305") {
                if (nonce.empty() || nonce.size() != 16) {
                    std::cerr << "POLY1305需要16字节nonce, 未设定合法once，自动生成nonce" << std::endl;
                    nonce.resize(16);
                    RAND_bytes((unsigned char *)nonce.data(), nonce.size());
                }
                params[0] = OSSL_PARAM_construct_octet_string(
                    OSSL_MAC_PARAM_IV,
                    const_cast<char*>(nonce.data()),
                    nonce.size()
                );
                params[1] = OSSL_PARAM_construct_end();
                return;
            }

            if (macName == "KMAC128" || macName == "KMAC256") {
                // 1. 密钥参数（部分场景需显式传递）
                params[0] = OSSL_PARAM_construct_octet_string(
                    OSSL_MAC_PARAM_KEY,
                    (void *)secret.data(),
                    secret.size()
                );
                std::string custom = getKMacCustom(algorithm);
                if (!custom.empty()) {
                    params[1] = OSSL_PARAM_construct_utf8_string(
                        OSSL_MAC_PARAM_CUSTOM,
                        (char *)(custom.data()),
                        custom.size()
                    );
                    params[2] = OSSL_PARAM_construct_end();
                } else {
                    params[1] = OSSL_PARAM_construct_end();
                }
                return;
            }
            std::cerr << "find none set_mac_params_by_name, use hmac config  " << hashName << " " << algorithm << std::endl;
            //default hmac
            params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, (char*)hashName.data(), hashName.size()),
            params[1] =OSSL_PARAM_END;
        }

        std::string MacSigner::sign(const std::string_view &plainData) {
            EVP_MAC *mac = EVP_MAC_fetch(nullptr, macName.data(), nullptr);
            if (mac == nullptr) {
                std::cout << "EVP_MAC_fetch failed " << algorithm << std::endl;
                printOpenSSLError();
                return "";
            }
            EVP_MAC_CTX *macCtx = EVP_MAC_CTX_new(mac);
            if (!macCtx) {
                std::cout << "EVP_MAC_fetch failed " << algorithm << std::endl;
                printOpenSSLError();
                EVP_MAC_free(mac);
                return "";
            }
            OSSL_PARAM params[4];
            set_mac_params_by_name(params, algorithm,  macName, hashName, secret, nonce);
            // 4. 初始化HMAC（传入密钥和参数）
            const unsigned char *key = (const unsigned char*)secret.data();
            if (EVP_MAC_init(macCtx,
                            key,
                            secret.size(),
                            params) != 1) {
                std::cout << "EVP_MAC_init failed " << algorithm << std::endl;
                printOpenSSLError();
                EVP_MAC_CTX_free(macCtx);
                EVP_MAC_free(mac);
                return "";
            }
            const unsigned char *in = ( const unsigned char *)plainData.data();
            if (EVP_MAC_update(macCtx, in, plainData.size()) != 1) {
                std::cout << "EVP_MAC_update failed " << algorithm << std::endl;
                printOpenSSLError();
                EVP_MAC_CTX_free(macCtx);
                EVP_MAC_free(mac);
                return "";
            }
            std::string result((EVP_MAX_MD_SIZE), '\0');
            size_t out_len = result.size();
            size_t outsize = result.size();
            unsigned char *out = (unsigned char *)result.data();
            if (EVP_MAC_final(macCtx, out, &out_len, outsize) != 1) {
                std::cout << "EVP_MAC_final failed " << algorithm << std::endl;
                printOpenSSLError();
                EVP_MAC_CTX_free(macCtx);
                EVP_MAC_free(mac);
                return "";
            }
            result.resize(out_len);
            EVP_MAC_CTX_free(macCtx);
            EVP_MAC_free(mac);
            return result;
        }

        std::string MacSigner::signToHex(const std::string_view &data) {
            return hex_encode(sign(data));
        }

        std::string MacSigner::signToBase64(const std::string_view &data) {
            return base64_encode(sign(data));
        }

        bool MacSigner::checkSign(const std::string_view &data, const std::string_view &expect_sign) {
            std::string now_sign = sign(data);
            if (now_sign.empty()) {
                return false;
            }
            return sign_cmp_equals(now_sign, expect_sign);
        }

        bool MacSigner::checkHexSign(const std::string_view &data, const std::string_view &sign_data) {
            std::string sign = hex_decode(sign_data);
            return checkSign(data, sign);
        }

        bool MacSigner::checkBase64Sign(const std::string_view &data, const std::string_view &sign_data) {
            std::string sign = base64_decode(sign_data);
            return checkSign(data, sign);
        }
    }
}

namespace camel {
    namespace crypto {
        namespace DigestUtils {

            inline std::string macSign(const std::string& algorithm, const std::string_view& data, const std::string_view& secret) {
                MacSigner macSigner(algorithm, secret);
                return macSigner.sign(data);
            }

            inline std::string macSignToHex(const std::string& algorithm, const std::string_view& data, const std::string_view& secret) {
                std::string secretStr(secret);
                MacSigner macSigner(algorithm, secretStr);
                return macSigner.signToHex(data);
            }

            inline std::string macSignToBase64(const std::string& algorithm, const std::string_view& data, const std::string_view& secret) {
                std::string secretStr(secret);
                MacSigner macSigner(algorithm, secretStr);
                return macSigner.signToBase64(data);
            }



            std::string hmac_sha256(const std::string_view& data, const std::string_view& secret) {
                return macSign("HMAC/SHA2-256", data, secret);
            }

            std::string hmac_sha256ToHex(const std::string_view& data, const std::string_view& secret) {
                return macSignToHex("HMAC/SHA2-256", data, secret);
            }

            std::string hmac_sha256ToBase64(const std::string_view& data, const std::string_view& secret) {
                return macSignToBase64("HMAC/SHA2-256", data, secret);
            }

            std::string hmac_sm3(const std::string_view& data, const std::string_view& secret) {
                return macSign("HMAC/SM3", data, secret);
            }
            std::string hmac_sm3ToHex(const std::string_view& data, const std::string_view& secret) {
                return macSignToHex("HMAC/SM3", data, secret);
            }
            std::string hmac_sm3ToBase64(const std::string_view& data, const std::string_view& secret) {
                return macSignToBase64("HMAC/SM3", data, secret);
            }
        }
    }
}

