//
// Created by baojian on 2025/8/18.
//

#include "ec.h"

#include <iostream>

#include "base64.h"
#include "config.h"
#include "hex.h"
#include "aes.h"

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>


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
            } else if ("der" == format || format == "raw") {
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
            } else if ("der" == format || format == "raw") {
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
            if (curveName == "sm2") {
                return "SM2";
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
                || this->curveName == "X448"
                || this->curveName == "SM2") {
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

        std::string ECKeyPairGenerator::getPublicKey(const std::string_view& format) {
            if ("hex" == format) {
                return getHexPublicKey();
            } else if ("base64" == format) {
                return getBase64PublicKey();
            } else if ("der" == format || format == "raw") {
                return getPublicKey();
            } else if ("pem" == format) {
                return getPemPublicKey();
            } else {
                return getPublicKey();
            }
        }
        std::string ECKeyPairGenerator::getPrivateKey(const std::string_view& format) {
            if ("hex" == format) {
                return getHexPrivateKey();
            } else if ("base64" == format) {
                return getBase64PrivateKey();
            } else if ("der" == format || format == "raw") {
                return getPrivateKey();
            } else if ("pem" == format) {
                return getPemPrivateKey();
            } else {
                return getPrivateKey();
            }
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


namespace camel {
    namespace crypto {
        HKDFSecretGenerator::HKDFSecretGenerator(const std::string_view &secret,
            const std::string_view &infoKey,
            const std::string_view &salt,
            const std::string_view &hashName,
            size_t secretLen) {
            EVP_KDF * kdf = EVP_KDF_fetch(nullptr, "HKDF", NULL);
            if (kdf == nullptr) {
                std::cerr << "HKDFSecretGenerator::HKDFSecretGenerator() Failed to EVP_KDF_fetch HKDF" << std::endl;
                printOpenSSLError();
                return;
            }
            EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(kdf);
            if (kctx == nullptr) {
                std::cerr << "HKDFSecretGenerator::HKDFSecretGenerator() Failed to EVP_KDF_CTX_new " << std::endl;
                printOpenSSLError();
                EVP_KDF_free(kdf);
                return;
            }
            {
                OSSL_PARAM params[] = {
                    OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, (char *)hashName.data(), hashName.size()),
                    OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, (void*)secret.data(), secret.size()),
                    OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, (void *)infoKey.data(), infoKey.size()),
                    OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, (void *)salt.data(), salt.size()),
                    OSSL_PARAM_END
                };
                if (secretLen <= 0) { //auto get gen legnth
                    const EVP_MD* md = EVP_get_digestbyname(hashName.data());
                    if (!md) {
                        std::cerr << "HKDFSecretGenerator::HKDFSecretGenerator() Failed to EVP_get_digestbyname " << hashName << std::endl;
                        printOpenSSLError();
                        EVP_KDF_CTX_free(kctx);
                        EVP_KDF_free(kdf);
                        return;
                    }
                    secretLen = EVP_MD_size(md);
                }
                genSecret.resize(secretLen);
                unsigned char *out = ( unsigned char *)genSecret.data();
                if (EVP_KDF_derive(kctx, out, secretLen, params) != 1) {
                    std::cerr << "HKDFSecretGenerator::HKDFSecretGenerator() Failed to EVP_KDF_derive " << hashName << std::endl;
                    printOpenSSLError();
                    EVP_KDF_CTX_free(kctx);
                    EVP_KDF_free(kdf);
                    return;
                }
            }
        }

        std::string HKDFSecretGenerator::getGenSecret() {
            return genSecret;
        }

        std::string HKDFSecretGenerator::getGenSecretHex() {
            return hex_encode(genSecret);
        }

        std::string HKDFSecretGenerator::getGenSecretBase64() {
            return base64_encode(genSecret);
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

        inline bool ECDSAAlgorithmHas(const std::string& algorithm, std::string_view target) {
            return algorithm.find(target) != std::string::npos;
        }

        bool configECDSASignParams(EVP_MD_CTX* ctx,  EVP_PKEY* key, const std::string& algorithm) {
            std::string signHash = OSSL_DIGEST_NAME_SHA2_256;
            if (ECDSAAlgorithmHas(algorithm,"MD5withECDSA")) {
                signHash = OSSL_DIGEST_NAME_MD5;
            } else if (ECDSAAlgorithmHas(algorithm,"SHA1withECDSA")) {
                signHash = OSSL_DIGEST_NAME_SHA1;
            } else if (ECDSAAlgorithmHas(algorithm,"SHA256withECDSA")) {
                signHash = OSSL_DIGEST_NAME_SHA2_256;
            } else if (ECDSAAlgorithmHas(algorithm,"SHA384withECDSA")) {
                signHash = OSSL_DIGEST_NAME_SHA2_384;
            } else if (ECDSAAlgorithmHas(algorithm,"SHA512withECDSA")) {
                signHash = OSSL_DIGEST_NAME_SHA2_512;
            } else if (ECDSAAlgorithmHas(algorithm,"SHA512/224withECDSA")) {
                signHash = OSSL_DIGEST_NAME_SHA2_512_224;
            } else if (ECDSAAlgorithmHas(algorithm,"SHA512/256withECDSA")) {
                signHash = OSSL_DIGEST_NAME_SHA2_512_256;
            } else if (ECDSAAlgorithmHas(algorithm,"SHA3_256withECDSA")) {
                signHash = OSSL_DIGEST_NAME_SHA3_256;
            } else if (ECDSAAlgorithmHas(algorithm,"SHA3_384withECDSA")) {
                signHash = OSSL_DIGEST_NAME_SHA3_384;
            } else if (ECDSAAlgorithmHas(algorithm,"SHA3_512withECDSA")) {
                signHash = OSSL_DIGEST_NAME_SHA3_512;
            }
            OSSL_PARAM params[] = {
                OSSL_PARAM_END
            };
            if (EVP_DigestSignInit_ex(ctx, NULL, signHash.data(), nullptr, nullptr,
                            key, params) == 0) {
                printOpenSSLError();
                return false;
            }
            return true;
        }

         bool configECDSAVerifyParams(EVP_MD_CTX* ctx,  EVP_PKEY* key, const std::string& algorithm) {
            std::string signHash = OSSL_DIGEST_NAME_SHA2_256;
            if (ECDSAAlgorithmHas(algorithm,"MD5withECDSA")) {
                signHash = OSSL_DIGEST_NAME_MD5;
            } else if (ECDSAAlgorithmHas(algorithm,"SHA1withECDSA")) {
                signHash = OSSL_DIGEST_NAME_SHA1;
            } else if (ECDSAAlgorithmHas(algorithm,"SHA256withECDSA")) {
                signHash = OSSL_DIGEST_NAME_SHA2_256;
            } else if (ECDSAAlgorithmHas(algorithm,"SHA384withECDSA")) {
                signHash = OSSL_DIGEST_NAME_SHA2_384;
            } else if (ECDSAAlgorithmHas(algorithm,"SHA512withECDSA")) {
                signHash = OSSL_DIGEST_NAME_SHA2_512;
            } else if (ECDSAAlgorithmHas(algorithm,"SHA512/224withECDSA")) {
                signHash = OSSL_DIGEST_NAME_SHA2_512_224;
            } else if (ECDSAAlgorithmHas(algorithm,"SHA512/256withECDSA")) {
                signHash = OSSL_DIGEST_NAME_SHA2_512_256;
            } else if (ECDSAAlgorithmHas(algorithm,"SHA3_256withECDSA")) {
                signHash = OSSL_DIGEST_NAME_SHA3_256;
            } else if (ECDSAAlgorithmHas(algorithm,"SHA3_384withECDSA")) {
                signHash = OSSL_DIGEST_NAME_SHA3_384;
            } else if (ECDSAAlgorithmHas(algorithm,"SHA3_512withECDSA")) {
                signHash = OSSL_DIGEST_NAME_SHA3_512;
            }
            OSSL_PARAM params[] = {
                OSSL_PARAM_END
            };
            if (EVP_DigestVerifyInit_ex(ctx, NULL, signHash.data(), nullptr, nullptr,
                            key, params) == 0) {
                printOpenSSLError();
                return false;
            }
            return true;
        }

    }
}



namespace camel {
    namespace crypto {
        ECDSAPrivateKeySigner::ECDSAPrivateKeySigner(const std::string_view& privateKey,
                  const std::string_view& format,
                  const std::string_view& algorithm) {
            this->algorithm = algorithm;
            this->format = format;
            this->privateKey = privateKey;
            this->externalEvpKey = nullptr;
        }


        std::string ECDSAPrivateKeySigner::sign(const std::string_view &plainText) const {
            if (plainText.empty()) {
                return "";
            }

            EVP_PKEY* evpKey = externalEvpKey;
            if (evpKey == nullptr) {
                evpKey = ECPrivateKeyFrom(privateKey, format);
            }
            if (evpKey == nullptr) {
                std::cerr << "ECDSAPrivateKeySigner::sign() Failed to create EVP_PKEY " << std::endl;
                printOpenSSLError();
                return "";
            }
            ECEvpKeyGuard evpKeyGuard(evpKey, externalEvpKey == nullptr);

            EVP_MD_CTX* ctx = EVP_MD_CTX_new();
            if (ctx == nullptr) {
                std::cerr << "ECDSAPrivateKeySigner::sign() Failed to create EVP_MD_CTX_new() " << std::endl;
                printOpenSSLError();
                return "";
            }
            if (!configECDSASignParams(ctx, evpKey, algorithm)) {
                EVP_MD_CTX_free(ctx);
                return "";
            }
            if (EVP_DigestSignUpdate(ctx, plainText.data(), plainText.size()) == 0) {
                std::cerr << "ECDSAPrivateKeySigner::sign() Failed to EVP_DigestSignUpdate " << std::endl;
                printOpenSSLError();
                EVP_MD_CTX_free(ctx);
                return "";
            }

            std::string buffer;
            buffer.resize(1024); // 目前secp521r1, 最大 150字节以内
            unsigned char *out = (unsigned char*) buffer.data();
            size_t outlen =  buffer.size();
            if (EVP_DigestSignFinal(ctx, out, &outlen) == 0) {
                std::cerr << "ECDSAPrivateKeySigner::sign() Failed to EVP_DigestSignFinal " << std::endl;
                printOpenSSLError();
                EVP_MD_CTX_free(ctx);
                return "";
            }
            EVP_MD_CTX_free(ctx);
            buffer.resize(outlen);

            return buffer;
        }

        std::string ECDSAPrivateKeySigner::signToHex(const std::string_view &plainText) const {
            return hex_encode(sign(plainText));
        }

        std::string ECDSAPrivateKeySigner::signToBase64(const std::string_view &plainText) const {
            return base64_encode(sign(plainText));
        }

    }
}



namespace camel {
    namespace crypto {
        ECDSAPublicKeyVerifier::ECDSAPublicKeyVerifier(const std::string_view& publicKey,
                  const std::string_view& format,
                  const std::string_view& algorithm) {
            this->algorithm = algorithm;
            this->format = format;
            this->publicKey = publicKey;
            this->externalEvpKey = nullptr;
        }


        bool ECDSAPublicKeyVerifier::verifySign(const std::string_view &sign, const std::string_view &data) const {
            if (sign.empty()
                || data.empty()) {
                return false;
            }

            EVP_PKEY* evpKey = externalEvpKey;
            if (evpKey == nullptr) {
                evpKey = ECPublicKeyFrom(publicKey, format);
            }
            if (evpKey == nullptr) {
                std::cerr << "ECDSAPublicKeyVerifier::verifySign() Failed to create EVP_PKEY " << std::endl;
                printOpenSSLError();
                return false;
            }
            ECEvpKeyGuard evpKeyGuard(evpKey, externalEvpKey == nullptr);

            EVP_MD_CTX* ctx = EVP_MD_CTX_new();
            if (ctx == nullptr) {
                std::cerr << "ECDSAPublicKeyVerifier::verifySign() Failed to create EVP_MD_CTX_new() " << std::endl;
                printOpenSSLError();
                return false;
            }
            if (!configECDSAVerifyParams(ctx, evpKey, algorithm)) {
                EVP_MD_CTX_free(ctx);
                return false;
            }
            if (EVP_DigestVerifyUpdate(ctx, data.data(), data.size()) == 0) {
                std::cerr << "ECDSAPublicKeyVerifier::verifySign() Failed to EVP_DigestVerifyUpdate " << std::endl;
                printOpenSSLError();
                EVP_MD_CTX_free(ctx);
                return false;
            }

            unsigned char *signData = (unsigned char*) sign.data();
            if (EVP_DigestVerifyFinal(ctx, signData, sign.size()) == 0) {
                std::cerr << "ECDSAPublicKeyVerifier::verifySign() Failed to EVP_DigestVerifyFinal " << std::endl;
                printOpenSSLError();
                EVP_MD_CTX_free(ctx);
                return false;
            }
            EVP_MD_CTX_free(ctx);
            return true;
        }

        bool ECDSAPublicKeyVerifier::verifyHexSign(const std::string_view &hexSign, const std::string_view &data) const {
            std::string sign = hex_decode(hexSign);
            return verifySign(sign, data);
        }


        bool ECDSAPublicKeyVerifier::verifyBase64Sign(const std::string_view &base64Sign, const std::string_view &data) const {
            std::string sign = base64_decode_url_safe(base64Sign);
            return verifySign(sign, data);
        }

    }
}


namespace camel {
    namespace crypto {
        bool configEDDSASignParams(EVP_MD_CTX* ctx,  EVP_PKEY* key) {
            OSSL_PARAM params[] = {
                OSSL_PARAM_END
            };
            // Notice that the digest name must NOT be used.
            if (EVP_DigestSignInit_ex(ctx, NULL, NULL, nullptr, nullptr,
                            key, params) == 0) {
                printOpenSSLError();
                return false;
            }
            return true;
        }

         bool configEDDSAVerifyParams(EVP_MD_CTX* ctx,  EVP_PKEY* key) {
            OSSL_PARAM params[] = {
                OSSL_PARAM_END
            };
            // Notice that the digest name must NOT be used.
            if (EVP_DigestVerifyInit_ex(ctx, NULL, NULL, nullptr, nullptr,
                            key, params) == 0) {
                printOpenSSLError();
                return false;
            }
            return true;
        }
    }
}


namespace camel {
    namespace crypto {
        EDDSAPrivateKeySigner::EDDSAPrivateKeySigner(const std::string_view& privateKey,
                  const std::string_view& format) {
            this->format = format;
            this->privateKey = privateKey;
            this->externalEvpKey = nullptr;
        }


        std::string EDDSAPrivateKeySigner::sign(const std::string_view &plainText) const {
            if (plainText.empty()) {
                return "";
            }

            EVP_PKEY* evpKey = externalEvpKey;
            if (evpKey == nullptr) {
                evpKey = ECPrivateKeyFrom(privateKey, format);
            }
            if (evpKey == nullptr) {
                std::cerr << "EDDSAPrivateKeySigner::sign() Failed to create EVP_PKEY " << std::endl;
                printOpenSSLError();
                return "";
            }
            ECEvpKeyGuard evpKeyGuard(evpKey, externalEvpKey == nullptr);

            EVP_MD_CTX* ctx = EVP_MD_CTX_new();
            if (ctx == nullptr) {
                std::cerr << "EDDSAPrivateKeySigner::sign() Failed to create EVP_MD_CTX_new() " << std::endl;
                printOpenSSLError();
                return "";
            }
            if (!configEDDSASignParams(ctx, evpKey)) {
                EVP_MD_CTX_free(ctx);
                return "";
            }


            std::string buffer;
            buffer.resize(1024); // 目前secp521r1, 最大 150字节以内
            unsigned char *out = (unsigned char*) buffer.data();
            size_t outlen =  buffer.size();
            const unsigned char *tbs = ( const unsigned char *) plainText.data();
            if (EVP_DigestSign(ctx, out, &outlen , tbs, plainText.size()) == 0) {
                std::cerr << "EDDSAPrivateKeySigner::sign() Failed to EVP_DigestSign " << std::endl;
                printOpenSSLError();
                EVP_MD_CTX_free(ctx);
                return "";
            }
            EVP_MD_CTX_free(ctx);
            buffer.resize(outlen);

            return buffer;
        }

        std::string EDDSAPrivateKeySigner::signToHex(const std::string_view &plainText) const {
            return hex_encode(sign(plainText));
        }

        std::string EDDSAPrivateKeySigner::signToBase64(const std::string_view &plainText) const {
            return base64_encode(sign(plainText));
        }

    }
}



namespace camel {
    namespace crypto {
        EDDSAPublicKeyVerifier::EDDSAPublicKeyVerifier(const std::string_view& publicKey,
                  const std::string_view& format) {
            this->format = format;
            this->publicKey = publicKey;
            this->externalEvpKey = nullptr;
        }


        bool EDDSAPublicKeyVerifier::verifySign(const std::string_view &sign, const std::string_view &data) const {
            if (sign.empty()
                || data.empty()) {
                return false;
            }

            EVP_PKEY* evpKey = externalEvpKey;
            if (evpKey == nullptr) {
                evpKey = ECPublicKeyFrom(publicKey, format);
            }
            if (evpKey == nullptr) {
                std::cerr << "EDDSAPrivateKeySigner::verifySign() Failed to create EVP_PKEY " << std::endl;
                printOpenSSLError();
                return false;
            }
            ECEvpKeyGuard evpKeyGuard(evpKey, externalEvpKey == nullptr);

            EVP_MD_CTX* ctx = EVP_MD_CTX_new();
            if (ctx == nullptr) {
                std::cerr << "EDDSAPrivateKeySigner::verifySign() Failed to create EVP_MD_CTX_new() " << std::endl;
                printOpenSSLError();
                return false;
            }
            if (!configEDDSAVerifyParams(ctx, evpKey)) {
                EVP_MD_CTX_free(ctx);
                return false;
            }
            const unsigned char *check_sign = (const unsigned char *)sign.data();
            const unsigned char *tbs = ( const unsigned char *) data.data();
            if (EVP_DigestVerify(ctx, check_sign, sign.size(),
                          tbs, data.size()) == 0) {
                std::cerr << "EDDSAPrivateKeySigner::verifySign() Failed to EVP_DigestVerify " << std::endl;
                printOpenSSLError();
                EVP_MD_CTX_free(ctx);
                return false;
            }
            EVP_MD_CTX_free(ctx);
            return true;
        }

        bool EDDSAPublicKeyVerifier::verifyHexSign(const std::string_view &hexSign, const std::string_view &data) const {
            std::string sign = hex_decode(hexSign);
            return verifySign(sign, data);
        }


        bool EDDSAPublicKeyVerifier::verifyBase64Sign(const std::string_view &base64Sign, const std::string_view &data) const {
            std::string sign = base64_decode_url_safe(base64Sign);
            return verifySign(sign, data);
        }

    }
}

namespace camel {
    namespace crypto {
        std::string getCurveName(EVP_PKEY* evpKey) {
            int pkey_id = EVP_PKEY_id(evpKey);

            //特殊椭圆曲线
            if (pkey_id == EVP_PKEY_X25519) {
                return "X25519";
            } else if (pkey_id == EVP_PKEY_X448) {
                return "X448";
            } else if (pkey_id == EVP_PKEY_ED25519) {
                return "ED25519";
            } else if (pkey_id == EVP_PKEY_ED448) {
                return "ED448";
            }

            // pkey_id == EVP_PKEY_EC
            // 传统椭圆曲线

            std::string curveName;
            curveName.resize(128);
            size_t outlen = 0;
            if (!EVP_PKEY_get_utf8_string_param(evpKey, OSSL_PKEY_PARAM_GROUP_NAME,
                                       curveName.data(), curveName.size(),
                                       &outlen)) {
                std::cerr << "ECIES getCurveName Failed to EVP_PKEY_get_utf8_string_param " << std::endl;
                printOpenSSLError();
                return "";
           }
            curveName.resize(outlen);
            return curveName;
        }

        std::string ecRandBytesLen(size_t len) {
            std::string buffer(len, '\0');
            unsigned char* iv = (unsigned char* )buffer.data();
            if (RAND_bytes(iv, len) != 1) {
                std::cerr << "ecRandBytesLen failed" << std::endl;
                printOpenSSLError();
                return "";
            }
            return buffer;
        }
    }
}

namespace camel {
    namespace crypto {
        inline std::string ECPrivateKeyToPKCS8(EVP_PKEY* pkey) {
            if (pkey == nullptr) {
                return "";
            }
            BIO* bio = BIO_new(BIO_s_mem());
            if (bio == nullptr) {
                std::cerr << "ECPrivateKeyToPKCS8 Failed to create memory BIO" << std::endl;
                printOpenSSLError();
                return "";
            }

            if (i2d_PKCS8PrivateKey_bio(bio, pkey, nullptr, nullptr, 0, nullptr, nullptr) != 1) {
                std::cerr << "ECPrivateKeyToPKCS8 Failed to write private key to BIO" << std::endl;
                printOpenSSLError();
                BIO_free(bio);
                return "";
            }
            char* buf;
            long len = BIO_get_mem_data(bio, &buf);
            if (len <= 0) {
                std::cerr << "ECPrivateKeyToPKCS8 Failed to write private key to BIO" << std::endl;
                printOpenSSLError();
                BIO_free(bio);
                return "";
            }
            std::string der(buf, len);
            BIO_free(bio);
            return der;
        }

        inline std::string ECPrivateKeyToBase64(EVP_PKEY* pkey) {
            return base64_encode(ECPrivateKeyToPKCS8(pkey));
        }
    }
}


namespace camel {
    namespace crypto {
        ECIESPrivateKeyDecryptor::ECIESPrivateKeyDecryptor(const std::string_view &privateKey, const std::string_view &format, const std::string_view &cipherAlgorithm) {
            this->privateKey = privateKey;
            this->format = format;
            this->cipherAlgorithm = cipherAlgorithm;
        }

        std::string ECIESPrivateKeyDecryptor::decrypt(const std::string_view &combineBase64Data) {
            EVP_PKEY* evpKey = nullptr;
            if (evpKey == nullptr) {
                evpKey = ECPrivateKeyFrom(privateKey, format);
            }
            if (evpKey == nullptr) {
                std::cerr << "ECIESPrivateKeyDecryptor::decrypt() Failed to create EVP_PKEY " << std::endl;
                printOpenSSLError();
                return "";
            }
            ECEvpKeyGuard evpKeyGuard(evpKey, true);
            std::string curveName = getCurveName(evpKey);
            if (curveName.empty()) {
                std::cerr << "ECIESPrivateKeyDecryptor::decrypt() Failed to getCurveName " << std::endl;
                printOpenSSLError();
                return "";
            }
            auto findIt = combineBase64Data.find_last_of('.');
            if (findIt == std::string::npos) {
                std::cerr << "ECIESPrivateKeyDecryptor::decrypt() illegal format encrypt data" << std::endl;
                printOpenSSLError();
                return "";
            }
            std::string_view publicKey = std::string_view(combineBase64Data.data() + findIt + 1, combineBase64Data.size() - findIt - 1);
            ECKeyPairGenerator keyGenerator(curveName);
            ECDHSharedSecretGenerator secretGenerator(ECPrivateKeyToBase64(evpKey), publicKey, "base64");
            std::string genSharedSecret = secretGenerator.getGenSecret();
            std::string firstCombineBlock = base64_decode(std::string_view(combineBase64Data.data(), findIt));
            if (firstCombineBlock.size() <= 32) {
                std::cerr << "ECIESPrivateKeyDecryptor::decrypt() illegal format encrypt data, infoKey(16 byte) and salt(16 byte) not right" << std::endl;
                printOpenSSLError();
                return "";
            }
            std::string_view infoKey = std::string_view(firstCombineBlock.data() + firstCombineBlock.size() - 32 , 16);
            std::string_view salt = std::string_view(firstCombineBlock.data() + firstCombineBlock.size() - 16, 16);
            HKDFSecretGenerator hkdfSecretGenerator(genSharedSecret, infoKey, salt, "SHA2-256");
            std::string hkdfSecret = hkdfSecretGenerator.getGenSecret();
            std::string_view cliperEncryptData = std::string_view(firstCombineBlock.data(), firstCombineBlock.size() - 32);
            AESDecryptor aesDecryptor(cipherAlgorithm, hkdfSecret, "raw");

            return aesDecryptor.decrypt(cliperEncryptData);
        }


    }
}

namespace camel {
    namespace crypto {
        ECIESPublicKeyEncryptor::ECIESPublicKeyEncryptor(const std::string_view &publicKey, const std::string_view &format, const std::string_view &cipherAlgorithm) {
            this->publicKey = publicKey;
            this->format = format;
            this->cipherAlgorithm = cipherAlgorithm;
        }

        std::string ECIESPublicKeyEncryptor::encrypt(const std::string_view &plainText) const {
            EVP_PKEY* evpKey = nullptr;
            if (evpKey == nullptr) {
                evpKey = ECPublicKeyFrom(publicKey, format);
            }
            if (evpKey == nullptr) {
                std::cerr << "ECIESPublicKeyEncryptor::encrypt() Failed to create EVP_PKEY " << std::endl;
                printOpenSSLError();
                return "";
            }
            ECEvpKeyGuard evpKeyGuard(evpKey, true);
            std::string curveName = getCurveName(evpKey);
            if (curveName.empty()) {
                std::cerr << "ECIESPublicKeyEncryptor::encrypt() Failed to getCurveName " << std::endl;
                printOpenSSLError();
                return "";
            }
            ECKeyPairGenerator keyGenerator(curveName);
            ECDHSharedSecretGenerator secretGenerator(keyGenerator.getPrivateKey(format), publicKey, format);
            std::string genSharedSecret = secretGenerator.getGenSecret();
            std::string infoKey = ecRandBytesLen(16);
            std::string salt = ecRandBytesLen(16);
            HKDFSecretGenerator hkdfSecretGenerator(genSharedSecret, infoKey, salt, "SHA2-256");
            std::string hkdfSecret = hkdfSecretGenerator.getGenSecret();

            AESEncryptor aesEncryptor(cipherAlgorithm, hkdfSecret, "raw");
            std::string encryptData = aesEncryptor.encrypt(plainText);
            encryptData.append(infoKey);
            encryptData.append(salt);
            std::string combineResult = base64_encode(encryptData);
            combineResult.append(".");
            combineResult.append(base64_encode(keyGenerator.getPublicKey()));

            return combineResult;
        }


    }
}