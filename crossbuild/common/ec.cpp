//
// Created by baojian on 2025/8/18.
//

#include "ec.h"

#include <iostream>

#include "base64.h"
#include "config.h"
#include "hex.h"
#include "openssl/core_names.h"
#include "openssl/evp.h"


namespace camel {
    namespace crypto {
        EVP_PKEY* ECPublicKeyFromPem(const std::string_view& pemKey) {
            EVP_PKEY* key = nullptr;
            BIO* bio = BIO_new_mem_buf(pemKey.data(), static_cast<int>(pemKey.size()));
            if (!bio) {
                std::cerr << "ECPublicKeyFromPem Failed to create memory BIO" << std::endl;
                printOpenSSLError();
                return key;
            }

            if (!PEM_read_bio_PUBKEY(bio, &key, nullptr, nullptr)) {
                std::cerr << "ECPublicKeyFromPem Failed to PEM_read_bio_PUBKEY " << std::endl;
                printOpenSSLError();
                BIO_free(bio);
                return key;
            }
            BIO_free(bio);
            return key;
        }

        EVP_PKEY* ECPublicKeyFromBase64(const std::string_view& base64Key) {
            return ECPublicKeyFromDer(base64_decode_url_safe(base64Key));
        }

        EVP_PKEY* ECPublicKeyFromHex(const std::string_view& hexKey) {
            return  ECPublicKeyFromDer(hex_decode(hexKey));
        }

        EVP_PKEY* ECPublicKeyFromDer(const std::string_view& derKey) {
            EVP_PKEY* key = nullptr;
            const unsigned char *in = (const unsigned char *)derKey.data();
            long length = derKey.size();
            if (d2i_PUBKEY(&key, &in, length) == nullptr) {
                std::cerr << "ECPublicKeyFromDer Failed to d2i_PUBKEY " << std::endl;
                printOpenSSLError();
                return nullptr;
            }
            return key;
        }

        EVP_PKEY* ECPublicKeyFromDerByBio(const std::string_view& derKey) {
            EVP_PKEY* key = nullptr;
            BIO* bio = BIO_new_mem_buf(derKey.data(), static_cast<int>(derKey.size()));
            if (!bio) {
                std::cerr << "ECPublicKeyFromDer Failed to create memory BIO" << std::endl;
                printOpenSSLError();
                return key;
            }
            if (d2i_PUBKEY_bio(bio, &key) == nullptr) {
                std::cerr << "ECPublicKeyFromDer Failed to d2i_PUBKEY_bio " << std::endl;
                printOpenSSLError();
                BIO_free(bio);
                return key;
            }
            BIO_free(bio);
            return key;
        }


        EVP_PKEY* ECPublicKeyFrom(const std::string_view& publicKey, const std::string_view& format) {
            if ("hex" == format) {
                return ECPublicKeyFromHex(publicKey);
            } else if ("base64" == format) {
                return ECPublicKeyFromBase64(publicKey);
            } else if ("der" == format) {
                return ECPublicKeyFromDer(publicKey);
            } else if ("pem" == format) {
                return ECPublicKeyFromPem(publicKey);
            } else {
                return ECPublicKeyFromPem(publicKey);
            }
        }

        EVP_PKEY* ECPrivateKeyFromPem(const std::string_view& pemKey) {
            EVP_PKEY* key = nullptr;
            BIO* bio = BIO_new_mem_buf(pemKey.data(), static_cast<int>(pemKey.size()));
            if (!bio) {
                std::cerr << "ECPrivateKeyFromPem Failed to create memory BIO" << std::endl;
                printOpenSSLError();
                return key;
            }
            if (!PEM_read_bio_PrivateKey(bio, &key, nullptr, nullptr)) {
                std::cerr << "ECPrivateKeyFromPem Failed to PEM_read_bio_PrivateKey " << std::endl;
                printOpenSSLError();
                BIO_free(bio);
                return key;
            }
            BIO_free(bio);
            return key;
        }

        EVP_PKEY* ECPrivateKeyFromDer(const std::string_view& derKey) {
            EVP_PKEY* key = nullptr;
            const unsigned char *in = (const unsigned char *)derKey.data();
            long length = derKey.size();
            if (d2i_AutoPrivateKey(&key, &in, length) == nullptr) {
                std::cerr << "ECPublicKeyFromDer Failed to d2i_AutoPrivateKey " << std::endl;
                printOpenSSLError();
                return nullptr;
            }
            return key;
        }

        EVP_PKEY* ECPrivateKeyFromDerByBio(const std::string_view& derKey) {
            EVP_PKEY* key = nullptr;
            BIO* bio = BIO_new_mem_buf(derKey.data(), static_cast<int>(derKey.size()));
            if (!bio) {
                std::cerr << "ECPrivateKeyFromDerByBio Failed to create memory BIO" << std::endl;
                printOpenSSLError();
                return key;
            }
            if (d2i_PrivateKey_bio(bio, &key) == nullptr) {
                std::cerr << "ECPrivateKeyFromDerByBio Failed to d2i_PrivateKey_bio " << std::endl;
                printOpenSSLError();
                BIO_free(bio);
                return key;
            }
            BIO_free(bio);
            return key;
        }


        EVP_PKEY* ECPrivateKeyFromBase64(const std::string_view& base64Key) {
            return ECPrivateKeyFromDer(base64_decode_url_safe(base64Key));
        }

        EVP_PKEY* ECPrivateKeyFromHex(const std::string_view& hexKey) {
            return ECPrivateKeyFromDer(hex_decode(hexKey));
        }

        EVP_PKEY* ECPrivateKeyFrom(const std::string_view& privateKey, const std::string_view& format) {
            if ("hex" == format) {
                return ECPrivateKeyFromHex(privateKey);
            } else if ("base64" == format) {
                return ECPrivateKeyFromBase64(privateKey);
            } else if ("der" == format) {
               return ECPrivateKeyFromDer(privateKey);
            } else if ("pem" == format) {
               return ECPrivateKeyFromPem(privateKey);
            } else {
                return ECPrivateKeyFromPem(privateKey);
            }
        }

    }
}


namespace camel {
    namespace crypto {
        inline bool ecCurveNameHas(const std::string_view& curveName, std::string_view target) {
            return curveName.find(target) != std::string::npos;
        }

        inline  std::string curveNameToLower(const std::string_view& curveName) {
            std::string lowerStr;
            lowerStr.reserve(curveName.size());
            std::transform(
                curveName.begin(),
                curveName.end(),
                std::back_inserter(lowerStr),
                [](unsigned char c) { return std::tolower(c); }
            );
            return lowerStr;
        }

        inline std::string curveNameToUpper(const std::string_view& curveName) {
            std::string upperStr;
            upperStr.reserve(curveName.size());
            std::transform(
                curveName.begin(),
                curveName.end(),
                std::back_inserter(upperStr),
                [](unsigned char c) { return std::toupper(c); }
            );
            return upperStr;
        }

        inline static std::string adaptCurveName(const std::string_view &curveNameView) {
            std::string curveName = curveNameToLower(curveNameView);
            if (curveName == "secp256r1") { //secp256r1 (P-256)	prime256v1
                return "P-256";
            }
            if (curveName == "secp384r1") {
                return "P-384";
            }
            if (curveName == "secp521r1") {
                return "P-521";
            }
            if (curveName == "ed25519") {
                return "ED25519";
            }
            if (curveName == "x25519") {
                return "X25519";
            }
            if (curveName == "x448") {
                return "X448";
            }
            if (curveName == "ed448") {
                return "ED448";
            }
            return curveNameToUpper(curveNameView);
        }
    }
}


namespace camel {
    namespace crypto {

        ECKeyPairGenerator::ECKeyPairGenerator(const std::string_view &curveName) {
            this->ctx = nullptr;
            this->pkey = nullptr;
            this->curveName = adaptCurveName(curveName);
            if (this->curveName == "ED25519"
                || this->curveName == "X25519"
                || this->curveName == "ED448"
                || this->curveName == "X448") {
                ctx = EVP_PKEY_CTX_new_from_name(nullptr, this->curveName.data(), nullptr);
                if (!ctx) {
                    std::cerr << " ECKeyPairGenerator Failed to EVP_PKEY_CTX_new_from_name EC" << std::endl;
                    printOpenSSLError();
                    return;
                }

                if (EVP_PKEY_keygen_init(ctx) <= 0) {
                    std::cerr << " ECKeyPairGenerator Failed to EVP_PKEY_keygen_init "<< this->curveName << std::endl;
                    printOpenSSLError();
                    return;
                }

                if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
                    std::cerr << " ECKeyPairGenerator Failed to EVP_PKEY_keygen "<< this->curveName << std::endl;
                    printOpenSSLError();
                    return;
                }
                return;
            }
            ctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
            if (!ctx) {
                std::cerr << " ECKeyPairGenerator Failed to EVP_PKEY_CTX_new_from_name EC" << std::endl;
                printOpenSSLError();
                return;
            }

            if (EVP_PKEY_keygen_init(ctx) <= 0) {
                std::cerr << " ECKeyPairGenerator Failed to EVP_PKEY_keygen_init "<< this->curveName << std::endl;
                printOpenSSLError();
                return;
            }
            {
                /*
                 * use_cofactordh This is an optional parameter.
                 * For many curves where the cofactor is 1, setting this has no effect.
                 */
                int use_cofactordh = 1;
                OSSL_PARAM params[] = {
                    OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                                                                     (char *)this->curveName.data(), this->curveName.size()),
                    OSSL_PARAM_construct_int(OSSL_PKEY_PARAM_USE_COFACTOR_ECDH,
                                                            &use_cofactordh),
                    OSSL_PARAM_END
                };
                if (!EVP_PKEY_CTX_set_params(ctx, params)) {
                    std::cerr << " ECKeyPairGenerator Failed to EVP_PKEY_CTX_set_params "<< this->curveName << std::endl;
                    printOpenSSLError();
                    return;
                }
            }

            if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
                std::cerr << " ECKeyPairGenerator Failed to EVP_PKEY_keygen "<< this->curveName << std::endl;
                printOpenSSLError();
                return;
            }
        }

        ECKeyPairGenerator::~ECKeyPairGenerator() {
            clean();
        }

        void ECKeyPairGenerator::clean() {
            if (ctx != nullptr) {
                EVP_PKEY_CTX_free(ctx);
                ctx = nullptr;
            }
            if (pkey != nullptr) {
                EVP_PKEY_free(pkey);
                pkey = nullptr;
            }
        }


         std::string ECKeyPairGenerator::getPublicKey() {
            if (pkey == nullptr) {
                return "";
            }

            BIO* bio = BIO_new(BIO_s_mem());
            if (bio == nullptr) {
                std::cerr << "ECKeyPairGenerator::getPublicKey() Failed to create memory BIO" << std::endl;
                printOpenSSLError();
                return "";
            }
            if (i2d_PUBKEY_bio(bio, pkey) != 1) {
                std::cerr << "ECKeyPairGenerator::getPublicKey() Failed to write public key to BIO" << std::endl;
                printOpenSSLError();
                BIO_free(bio);
                return "";
            }
            char* buf;
            long len = BIO_get_mem_data(bio, &buf);
            if (len <= 0) {
                std::cerr << "ECKeyPairGenerator::getPublicKey() Failed to write public key to BIO" << std::endl;
                printOpenSSLError();
                BIO_free(bio);
                return "";
            }
            std::string der(buf, len);
            BIO_free(bio);
            return der;
        }

        std::string ECKeyPairGenerator::getPrivateKey() {
            if (pkey == nullptr) {
                return "";
            }
            BIO* bio = BIO_new(BIO_s_mem());
            if (bio == nullptr) {
                std::cerr << "ECKeyPairGenerator::getPrivateKey() Failed to create memory BIO" << std::endl;
                printOpenSSLError();
                return "";
            }

            if (i2d_PKCS8PrivateKey_bio(bio, pkey, nullptr, nullptr, 0, nullptr, nullptr) != 1) {
                std::cerr << "ECKeyPairGenerator::getPrivateKey() Failed to write private key to BIO" << std::endl;
                printOpenSSLError();
                BIO_free(bio);
                return "";
            }
            char* buf;
            long len = BIO_get_mem_data(bio, &buf);
            if (len <= 0) {
                std::cerr << "ECKeyPairGenerator::getPrivateKey() Failed to write private key to BIO" << std::endl;
                printOpenSSLError();
                BIO_free(bio);
                return "";
            }
            std::string der(buf, len);
            BIO_free(bio);
            return der;
        }

        std::string ECKeyPairGenerator::getHexPublicKey() {
            return hex_encode(getPublicKey());
        }

        std::string ECKeyPairGenerator::getHexPrivateKey() {
            return hex_encode(getPrivateKey());
        }

        std::string ECKeyPairGenerator::getBase64NewLinePublicKey() {
            return base64_encode_new_line(getPublicKey());
        }

        std::string ECKeyPairGenerator::getBase64NewLinePrivateKey() {
            return base64_encode_new_line(getPrivateKey());
        }

        std::string  ECKeyPairGenerator::getBase64PublicKey() {
            return base64_encode(getPublicKey());
        }
        std::string ECKeyPairGenerator::getBase64PrivateKey() {
            return base64_encode(getPrivateKey());
        }

        std::string ECKeyPairGenerator::getPemPrivateKey() {
            if (pkey == nullptr) {
                return "";
            }
            BIO* bio = BIO_new(BIO_s_mem());
            if (bio == nullptr) {
                std::cerr << "ECKeyPairGenerator::getPemPrivateKey() Failed to create memory BIO" << std::endl;
                printOpenSSLError();
                return "";
            }
            if (PEM_write_bio_PrivateKey(bio, pkey, nullptr, nullptr, 0, nullptr, nullptr) != 1) {
                std::cerr << "ECKeyPairGenerator::getPemPrivateKey() Failed to write private key to BIO" << std::endl;
                printOpenSSLError();
                BIO_free(bio);
                return "";
            }
            char* bioData = nullptr;
            long bioLen = BIO_get_mem_data(bio, &bioData); // 获取内存地址和长度
            std::string privateKey;
            if (bioLen > 0 && bioData) {
                privateKey.reserve(bioLen);
                privateKey.assign(bioData, bioLen);
            }
            BIO_free(bio);
            return privateKey;
        }

        std::string ECKeyPairGenerator::getPemPublicKey() {
            if (pkey == nullptr) {
                return "";
            }
            BIO* bio = BIO_new(BIO_s_mem());
            if (bio == nullptr) {
                std::cerr << "ECKeyPairGenerator::getPemPublicKey() Failed to create memory BIO" << std::endl;
                printOpenSSLError();
                return "";
            }
            if (PEM_write_bio_PUBKEY(bio, pkey) != 1) {
                std::cerr << "ECKeyPairGenerator::getPemPublicKey() Failed to write private key to BIO" << std::endl;
                printOpenSSLError();
                BIO_free(bio);
                return "";
            }
            char* bioData = nullptr;
            long bioLen = BIO_get_mem_data(bio, &bioData); // 获取内存地址和长度
            std::string publicKey;
            if (bioLen > 0 && bioData) {
                publicKey.reserve(bioLen);
                publicKey.assign(bioData, bioLen);
            }
            BIO_free(bio);
            return publicKey;
        }

    }
}

namespace camel {
    namespace crypto {
        class ECEvpKeyGuard {
        public:
            explicit ECEvpKeyGuard(EVP_PKEY* evpKey, bool needFree) {
                this->evpKey = evpKey;
                this->needFree = needFree;
            }
            ~ECEvpKeyGuard() {
                if (needFree) {
                    if (evpKey != nullptr) {
                        EVP_PKEY_free(evpKey);
                        evpKey = nullptr;
                    }
                }
            }
        public:
            ECEvpKeyGuard(ECEvpKeyGuard const&)            = delete;
            ECEvpKeyGuard& operator=(ECEvpKeyGuard const&) = delete;
        private:
            EVP_PKEY* evpKey;
            bool  needFree;
        };

        inline bool ecAlgorithmHas(const std::string& algorithm, std::string_view target) {
            return algorithm.find(target) != std::string::npos;
        }

        # define EC_OSSL_PARAM_KDF_DIGEST "kdf-digest"
        # define EC_OSSL_PARAM_KDF_DIGEST_PROPS "kdf-digest-props"
        # define EC_OSSL_PARAM_KDF_OUTLEN "kdf-outlen"
        # define EC_OSSL_PARAM_KDF_TYPE "kdf-type"
        # define EC_OSSL_PARAM_KDF_UKM "kdf-ukm"

        bool ecConfigEncryptParams(EVP_PKEY* evpKey, EVP_PKEY_CTX *ctx, const std::string& algorithm) {
          if (EVP_PKEY_id(evpKey) == EVP_PKEY_SM2) {
              /**
              std::string mode = "AES-256-GCM";
              OSSL_PARAM params[] = {
                  OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_CIPHER, "sm4-cbc", 0), // 国密推荐 SM4
        OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAm, "sm3", 0),
                OSSL_PARAM_END
               };
              if (EVP_PKEY_CTX_set_params(ctx, params) <= 0) {
                  std::cerr << "ecConfigEncryptParams Failed to EVP_PKEY_CTX_set_params" << algorithm << std::endl;
                  printOpenSSLError();
                  return false;
              }
              return true;*/
          }
          if (ecAlgorithmHas(algorithm, "AES-256-GCM")) {
                std::string mode = "AES-256-GCM";
                OSSL_PARAM params[] = {
                     OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_CIPHER, mode.data(), mode.size()),
                    OSSL_PARAM_construct_utf8_string(EC_OSSL_PARAM_KDF_TYPE, mode.data(), mode.size()),
                  OSSL_PARAM_END
                 };
                if (EVP_PKEY_encrypt_init_ex(ctx, params) <= 0) {
                    std::cerr << "ecConfigEncryptParams Failed to EVP_PKEY_CTX_set_params" << algorithm << std::endl;
                    printOpenSSLError();
                    return false;
                }
                return true;
            }
            std::cerr << "ecConfigEncryptParams unsupported mode " << algorithm << std::endl;
            return false;
        }
    }
}

namespace camel {
    namespace crypto {

        ECPublicKeyEncryptor::ECPublicKeyEncryptor(const std::string_view &publicKey,
            const std::string_view &format,
            const std::string_view& algorithm) {
            this->format = format;
            this->algorithm = algorithm;
            this->publicKey = publicKey;
            this->externalEvpKey = nullptr;
            std::transform(this->algorithm.begin(), this->algorithm.end(), this->algorithm.begin(), ::toupper);
        }

        std::string ECPublicKeyEncryptor::encrypt(const std::string_view &plainText) const {
            if (plainText.empty()) {
                return "";
            }
            EVP_PKEY* evpKey = externalEvpKey;
            if (evpKey == nullptr) {
                evpKey = ECPublicKeyFrom(publicKey, format);
            }
            if (evpKey == nullptr) {
                std::cerr << "ECPublicKeyEncryptor::decrypt() Failed to create EVP_PKEY_CTX_new " << std::endl;
                printOpenSSLError();
                return "";
            }
            ECEvpKeyGuard evpKeyGuard(evpKey, externalEvpKey == nullptr);

           // std::cout << EVP_PKEY_supports(evpKey, EVP_PKEY_OP_ENCRYPT) << std::endl;
            //if (EVP_PKEY_id(evpKey) != EVP_PKEY_EC) {
             //   std::cerr << "ECPublicKeyEncryptor::encrypt() not EVP_PKEY_EC key" << std::endl;
            //    printOpenSSLError();
            //    return "";
            //}
            EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_pkey(nullptr, evpKey, nullptr);
            if (ctx == nullptr) {
                std::cerr << "ECPublicKeyEncryptor::encrypt() Failed to create EVP_PKEY_CTX_new_from_pkey" << std::endl;
                printOpenSSLError();
                return "";
            }



            if (!ecConfigEncryptParams(evpKey, ctx, algorithm)) {
                EVP_PKEY_CTX_free(ctx);
                return "";
            }

            std::string buffer;
            int bigBufferSize = plainText.size()*2;
            buffer.resize(std::max(bigBufferSize, 2048));
            unsigned char *in = (unsigned char *)plainText.data();
            unsigned char *out = (unsigned char *)buffer.data();
            size_t totalLength = 0;
            size_t outlen = buffer.size() - totalLength;
            if (EVP_PKEY_encrypt(ctx, out, &outlen, in, plainText.size()) <= 0) {
                std::cerr << "ECPublicKeyEncryptor::encrypt() Failed to EVP_PKEY_encrypt " << std::endl;
                printOpenSSLError();
                EVP_PKEY_CTX_free(ctx);
                return "";
            }
            totalLength += outlen;
            buffer.resize(totalLength);
            EVP_PKEY_CTX_free(ctx);
            return buffer;
        }


        std::string ECPublicKeyEncryptor::encryptToBase64(const std::string_view &plainText) const {
            return base64_encode(encrypt(plainText));
        }

        std::string ECPublicKeyEncryptor::encryptToHex(const std::string_view &plainText) const {
            return hex_encode(encrypt(plainText));
        }
    }
}

namespace camel {
    namespace crypto {
        ECDHSharedSecretGenerator::ECDHSharedSecretGenerator(const std::string_view &localPrivateKey, const std::string_view &remotePublicKey, const std::string_view &format) {
            {
                EVP_PKEY *localPKey  = ECPrivateKeyFrom(localPrivateKey, format);
                if (localPKey == nullptr) {
                    std::cerr << "ECDHSharedSecretGenerator::ECDHSharedSecretGenerator() Failed to call ECPrivateKeyFrom" << std::endl;
                    printOpenSSLError();
                    return;
                }
                EVP_PKEY *remotePKey = ECPublicKeyFrom(remotePublicKey, format);
                if (remotePKey == nullptr) {
                    std::cerr << "ECDHSharedSecretGenerator::ECDHSharedSecretGenerator() Failed to call ECPublicKeyFrom" << std::endl;
                    printOpenSSLError();
                    EVP_PKEY_free(localPKey);
                    return;
                }
                EVP_PKEY_CTX * deriveCtx = EVP_PKEY_CTX_new_from_pkey(nullptr, localPKey, nullptr);
                if (deriveCtx == nullptr) {
                    std::cerr << "ECDHSharedSecretGenerator::ECDHSharedSecretGenerator() Failed to call EVP_PKEY_CTX_new_from_pkey" << std::endl;
                    printOpenSSLError();
                    EVP_PKEY_free(localPKey);
                    EVP_PKEY_free(remotePKey);
                    return;
                }
                if (EVP_PKEY_derive_init(deriveCtx) <= 0) {
                    std::cerr << "ECDHSharedSecretGenerator::ECDHSharedSecretGenerator() Failed to call EVP_PKEY_derive_init " << std::endl;
                    printOpenSSLError();
                    EVP_PKEY_free(localPKey);
                    EVP_PKEY_free(remotePKey);
                    EVP_PKEY_CTX_free(deriveCtx);
                    return;
                }
                if (EVP_PKEY_derive_set_peer(deriveCtx, remotePKey) <= 0) {
                    std::cerr << "ECDHSharedSecretGenerator::ECDHSharedSecretGenerator() Failed to set peer" << std::endl;
                    printOpenSSLError();
                    EVP_PKEY_free(localPKey);
                    EVP_PKEY_free(remotePKey);
                    EVP_PKEY_CTX_free(deriveCtx);
                    return;
                }

                size_t keylen = 0;
                {
                    if (EVP_PKEY_derive(deriveCtx, nullptr, &keylen) <= 0) {
                        std::cerr << "ECDHSharedSecretGenerator::ECDHSharedSecretGenerator() Failed to get secret len" << std::endl;
                        printOpenSSLError();
                        EVP_PKEY_free(localPKey);
                        EVP_PKEY_free(remotePKey);
                        EVP_PKEY_CTX_free(deriveCtx);
                        return;
                    }
                }
                genSecret.resize(std::max((int)keylen, 512));
                unsigned char *key = (unsigned char *)genSecret.data();
                if (EVP_PKEY_derive(deriveCtx, key, &keylen) <= 0) {
                    std::cerr << "ECDHSharedSecretGenerator::ECDHSharedSecretGenerator() Failed to derive secret" << std::endl;
                    printOpenSSLError();
                    EVP_PKEY_free(localPKey);
                    EVP_PKEY_free(remotePKey);
                    EVP_PKEY_CTX_free(deriveCtx);
                    return;
                }
                genSecret.resize(keylen);
            }
        }

        std::string ECDHSharedSecretGenerator::getGenSecret() {
            return genSecret;
        }

        std::string ECDHSharedSecretGenerator::getGenSecretHex() {
            return hex_encode(genSecret);
        }

        std::string ECDHSharedSecretGenerator::getGenSecretBase64() {
            return base64_encode(genSecret);
        }
    }
}