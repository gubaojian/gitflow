//
// Created by efurture on 25-8-19.
//

#include "sm2.h"

#include <iostream>

#include "base64.h"
#include "config.h"
#include "hex.h"
#include "openssl/asn1t.h"
#include "openssl/core_names.h"
#include "openssl/evp.h"


namespace camel {
    namespace crypto {
        SM2KeyPairGenerator::SM2KeyPairGenerator() {
            this->ctx = nullptr;
            this->pkey = nullptr;
            std::string curveName = "SM2";
            ctx = EVP_PKEY_CTX_new_from_name(nullptr, "SM2", nullptr);
            if (!ctx) {
                std::cerr << " SM2KeyPairGenerator Failed to EVP_PKEY_CTX_new_from_name SM2" << std::endl;
                printOpenSSLError();
                return;
            }

            if (EVP_PKEY_keygen_init(ctx) <= 0) {
                std::cerr << " SM2KeyPairGenerator Failed to EVP_PKEY_keygen_init "<< curveName << std::endl;
                printOpenSSLError();
                return;
            }
            {
                /*
                 * use_cofactordh This is an optional parameter.
                 * For many curves where the cofactor is 1, setting this has no effSM2t.
                 */
                int use_cofactordh = 1;
                OSSL_PARAM params[] = {
                    OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                                                                     (char *)curveName.data(), curveName.size()),
                    OSSL_PARAM_construct_int(OSSL_PKEY_PARAM_USE_COFACTOR_ECDH,
                                                            &use_cofactordh),
                    OSSL_PARAM_END
                };
                if (!EVP_PKEY_CTX_set_params(ctx, params)) {
                    std::cerr << " SM2KeyPairGenerator Failed to EVP_PKEY_CTX_set_params "<< curveName << std::endl;
                    printOpenSSLError();
                    return;
                }
            }

            if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
                std::cerr << " SM2KeyPairGenerator Failed to EVP_PKEY_keygen "<<  curveName << std::endl;
                printOpenSSLError();
                return;
            }
        }

        SM2KeyPairGenerator::~SM2KeyPairGenerator() {
            clean();
        }

        void SM2KeyPairGenerator::clean() {
            if (ctx != nullptr) {
                EVP_PKEY_CTX_free(ctx);
                ctx = nullptr;
            }
            if (pkey != nullptr) {
                EVP_PKEY_free(pkey);
                pkey = nullptr;
            }
        }


         std::string SM2KeyPairGenerator::getPublicKey() {
            if (pkey == nullptr) {
                return "";
            }

            BIO* bio = BIO_new(BIO_s_mem());
            if (bio == nullptr) {
                std::cerr << "SM2KeyPairGenerator::getPublicKey() Failed to create memory BIO" << std::endl;
                printOpenSSLError();
                return "";
            }
            if (i2d_PUBKEY_bio(bio, pkey) != 1) {
                std::cerr << "SM2KeyPairGenerator::getPublicKey() Failed to write public key to BIO" << std::endl;
                printOpenSSLError();
                BIO_free(bio);
                return "";
            }
            char* buf;
            long len = BIO_get_mem_data(bio, &buf);
            if (len <= 0) {
                std::cerr << "SM2KeyPairGenerator::getPublicKey() Failed to write public key to BIO" << std::endl;
                printOpenSSLError();
                BIO_free(bio);
                return "";
            }
            std::string der(buf, len);
            BIO_free(bio);
            return der;
        }

        std::string SM2KeyPairGenerator::getPrivateKey() {
            if (pkey == nullptr) {
                return "";
            }
            BIO* bio = BIO_new(BIO_s_mem());
            if (bio == nullptr) {
                std::cerr << "SM2KeyPairGenerator::getPrivateKey() Failed to create memory BIO" << std::endl;
                printOpenSSLError();
                return "";
            }

            if (i2d_PKCS8PrivateKey_bio(bio, pkey, nullptr, nullptr, 0, nullptr, nullptr) != 1) {
                std::cerr << "SM2KeyPairGenerator::getPrivateKey() Failed to write private key to BIO" << std::endl;
                printOpenSSLError();
                BIO_free(bio);
                return "";
            }
            char* buf;
            long len = BIO_get_mem_data(bio, &buf);
            if (len <= 0) {
                std::cerr << "SM2KeyPairGenerator::getPrivateKey() Failed to write private key to BIO" << std::endl;
                printOpenSSLError();
                BIO_free(bio);
                return "";
            }
            std::string der(buf, len);
            BIO_free(bio);
            return der;
        }

        std::string SM2KeyPairGenerator::getHexPublicKey() {
            return hex_encode(getPublicKey());
        }

        std::string SM2KeyPairGenerator::getHexPrivateKey() {
            return hex_encode(getPrivateKey());
        }

        std::string SM2KeyPairGenerator::getBase64NewLinePublicKey() {
            return base64_encode_new_line(getPublicKey());
        }

        std::string SM2KeyPairGenerator::getBase64NewLinePrivateKey() {
            return base64_encode_new_line(getPrivateKey());
        }

        std::string  SM2KeyPairGenerator::getBase64PublicKey() {
            return base64_encode(getPublicKey());
        }
        std::string SM2KeyPairGenerator::getBase64PrivateKey() {
            return base64_encode(getPrivateKey());
        }

        std::string SM2KeyPairGenerator::getPemPrivateKey() {
            if (pkey == nullptr) {
                return "";
            }
            BIO* bio = BIO_new(BIO_s_mem());
            if (bio == nullptr) {
                std::cerr << "SM2KeyPairGenerator::getPemPrivateKey() Failed to create memory BIO" << std::endl;
                printOpenSSLError();
                return "";
            }
            if (PEM_write_bio_PrivateKey(bio, pkey, nullptr, nullptr, 0, nullptr, nullptr) != 1) {
                std::cerr << "SM2KeyPairGenerator::getPemPrivateKey() Failed to write private key to BIO" << std::endl;
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

        std::string SM2KeyPairGenerator::getPemPublicKey() {
            if (pkey == nullptr) {
                return "";
            }
            BIO* bio = BIO_new(BIO_s_mem());
            if (bio == nullptr) {
                std::cerr << "SM2KeyPairGenerator::getPemPublicKey() Failed to create memory BIO" << std::endl;
                printOpenSSLError();
                return "";
            }
            if (PEM_write_bio_PUBKEY(bio, pkey) != 1) {
                std::cerr << "SM2KeyPairGenerator::getPemPublicKey() Failed to write private key to BIO" << std::endl;
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
        EVP_PKEY* SM2PublicKeyFromPem(const std::string& pemKey) {
            EVP_PKEY* key = nullptr;
            BIO* bio = BIO_new_mem_buf(pemKey.data(), static_cast<int>(pemKey.size()));
            if (!bio) {
                std::cerr << "SM2PublicKeyFromPem Failed to create memory BIO" << std::endl;
                printOpenSSLError();
                return key;
            }

            if (!PEM_read_bio_PUBKEY(bio, &key, nullptr, nullptr)) {
                std::cerr << "SM2PublicKeyFromPem Failed to PEM_read_bio_PUBKEY " << std::endl;
                printOpenSSLError();
                BIO_free(bio);
                return key;
            }
            BIO_free(bio);
            return key;
        }

        EVP_PKEY* SM2PublicKeyFromBase64(const std::string& base64Key) {
            return SM2PublicKeyFromDer(base64_decode_url_safe(base64Key));
        }

        EVP_PKEY* SM2PublicKeyFromHex(const std::string& hexKey) {
            return  SM2PublicKeyFromDer(hex_decode(hexKey));
        }

        EVP_PKEY* SM2PublicKeyFromDer(const std::string& derKey) {
            EVP_PKEY* key = nullptr;
            const unsigned char *in = (const unsigned char *)derKey.data();
            long length = derKey.size();
            if (d2i_PUBKEY(&key, &in, length) == nullptr) {
                std::cerr << "SM2PublicKeyFromDer Failed to d2i_PUBKEY " << std::endl;
                printOpenSSLError();
                return nullptr;
            }
            return key;
        }

        EVP_PKEY* SM2PublicKeyFromDerByBio(const std::string& derKey) {
            EVP_PKEY* key = nullptr;
            BIO* bio = BIO_new_mem_buf(derKey.data(), static_cast<int>(derKey.size()));
            if (!bio) {
                std::cerr << "SM2PublicKeyFromDer Failed to create memory BIO" << std::endl;
                printOpenSSLError();
                return key;
            }
            if (d2i_PUBKEY_bio(bio, &key) == nullptr) {
                std::cerr << "SM2PublicKeyFromDer Failed to d2i_PUBKEY_bio " << std::endl;
                printOpenSSLError();
                BIO_free(bio);
                return key;
            }
            BIO_free(bio);
            return key;
        }


        EVP_PKEY* SM2PublicKeyFrom(const std::string& publicKey, const std::string& format) {
            if ("hex" == format) {
                return SM2PublicKeyFromHex(publicKey);
            } else if ("base64" == format) {
                return SM2PublicKeyFromBase64(publicKey);
            } else if ("der" == format) {
                return SM2PublicKeyFromDer(publicKey);
            } else if ("pem" == format) {
                return SM2PublicKeyFromPem(publicKey);
            } else {
                return SM2PublicKeyFromPem(publicKey);
            }
        }

        EVP_PKEY* SM2PrivateKeyFromPem(const std::string& pemKey) {
            EVP_PKEY* key = nullptr;
            BIO* bio = BIO_new_mem_buf(pemKey.data(), static_cast<int>(pemKey.size()));
            if (!bio) {
                std::cerr << "SM2PrivateKeyFromPem Failed to create memory BIO" << std::endl;
                printOpenSSLError();
                return key;
            }
            if (!PEM_read_bio_PrivateKey(bio, &key, nullptr, nullptr)) {
                std::cerr << "SM2PrivateKeyFromPem Failed to PEM_read_bio_PrivateKey " << std::endl;
                printOpenSSLError();
                BIO_free(bio);
                return key;
            }
            BIO_free(bio);
            return key;
        }

        EVP_PKEY* SM2PrivateKeyFromDer(const std::string& derKey) {
            EVP_PKEY* key = nullptr;
            const unsigned char *in = (const unsigned char *)derKey.data();
            long length = derKey.size();
            if (d2i_PrivateKey(EVP_PKEY_SM2, &key, &in, length) == nullptr) {
                std::cerr << "SM2PublicKeyFromDer Failed to d2i_PrivateKey " << std::endl;
                printOpenSSLError();
                return nullptr;
            }
            return key;
        }

        EVP_PKEY* SM2PrivateKeyFromDerByBio(const std::string& derKey) {
            EVP_PKEY* key = nullptr;
            BIO* bio = BIO_new_mem_buf(derKey.data(), static_cast<int>(derKey.size()));
            if (!bio) {
                std::cerr << "SM2PrivateKeyFromDerByBio Failed to create memory BIO" << std::endl;
                printOpenSSLError();
                return key;
            }
            if (d2i_PrivateKey_bio(bio, &key) == nullptr) {
                std::cerr << "SM2PrivateKeyFromDerByBio Failed to d2i_PrivateKey_bio " << std::endl;
                printOpenSSLError();
                BIO_free(bio);
                return key;
            }
            BIO_free(bio);
            return key;
        }


        EVP_PKEY* SM2PrivateKeyFromBase64(const std::string& base64Key) {
            return SM2PrivateKeyFromDer(base64_decode_url_safe(base64Key));
        }

        EVP_PKEY* SM2PrivateKeyFromHex(const std::string& hexKey) {
            return SM2PrivateKeyFromDer(hex_decode(hexKey));
        }

        EVP_PKEY* SM2PrivateKeyFrom(const std::string& privateKey, const std::string& format) {
            if ("hex" == format) {
                return SM2PrivateKeyFromHex(privateKey);
            } else if ("base64" == format) {
                return SM2PrivateKeyFromBase64(privateKey);
            } else if ("der" == format) {
               return SM2PrivateKeyFromDer(privateKey);
            } else if ("pem" == format) {
               return SM2PrivateKeyFromPem(privateKey);
            } else {
                return SM2PrivateKeyFromPem(privateKey);
            }
        }

    }
}


namespace camel {
    namespace crypto {

        class SM2EvpKeyGuard {
        public:
            explicit SM2EvpKeyGuard(EVP_PKEY* evpKey, bool needFree) {
                this->evpKey = evpKey;
                this->needFree = needFree;
            }
            ~SM2EvpKeyGuard() {
                if (needFree) {
                    if (evpKey != nullptr) {
                        EVP_PKEY_free(evpKey);
                        evpKey = nullptr;
                    }
                }
            }
        public:
            SM2EvpKeyGuard(SM2EvpKeyGuard const&)            = delete;
            SM2EvpKeyGuard& operator=(SM2EvpKeyGuard const&) = delete;
        private:
            EVP_PKEY* evpKey;
            bool  needFree;
        };

        inline bool sm2AlgorithmHas(const std::string& algorithm, std::string_view target) {
            return algorithm.find(target) != std::string::npos;
        }


        bool sm2ConfigEncryptParams(EVP_PKEY* evpKey, EVP_PKEY_CTX *ctx, const std::string& dataModeFlag) {
            OSSL_PARAM params[] = {
             OSSL_PARAM_END
            };
            if (EVP_PKEY_encrypt_init_ex(ctx, params) <= 0) {
                std::cerr << "sm2ConfigEncryptParams Failed to EVP_PKEY_CTX_set_params" << std::endl;
                printOpenSSLError();
                return false;
            }
            return true;
        }

        bool sm2ConfigDecryptParams(EVP_PKEY* evpKey, EVP_PKEY_CTX *ctx, const std::string& dataModeFlag) {
            OSSL_PARAM params[] = {
                OSSL_PARAM_END
            };
            if (EVP_PKEY_decrypt_init_ex(ctx, params) <= 0) {
                std::cerr << "sm2ConfigDecryptParams Failed to EVP_PKEY_CTX_set_params" << std::endl;
                printOpenSSLError();
                return false;
            }
            return true;
        }

        /**
         * 和 sm2_crypt.c 结构保持一致
         */
        typedef struct CAMEL_SM2_Ciphertext_st CAMEL_SM2_Ciphertext;
        DECLARE_ASN1_FUNCTIONS(CAMEL_SM2_Ciphertext)

        struct CAMEL_SM2_Ciphertext_st {
            BIGNUM *C1x;
            BIGNUM *C1y;
            ASN1_OCTET_STRING *C3;
            ASN1_OCTET_STRING *C2;
        };

        ASN1_SEQUENCE(CAMEL_SM2_Ciphertext) = {
            ASN1_SIMPLE(CAMEL_SM2_Ciphertext, C1x, BIGNUM),
            ASN1_SIMPLE(CAMEL_SM2_Ciphertext, C1y, BIGNUM),
            ASN1_SIMPLE(CAMEL_SM2_Ciphertext, C3, ASN1_OCTET_STRING),
            ASN1_SIMPLE(CAMEL_SM2_Ciphertext, C2, ASN1_OCTET_STRING),
        } ASN1_SEQUENCE_END(CAMEL_SM2_Ciphertext)

        IMPLEMENT_ASN1_FUNCTIONS(CAMEL_SM2_Ciphertext);

        /**
         * sm2_crypt.c 检查是否是openssl输出ASN1结构
         * openssl ansi format
         * @param source
         * @return
         */
        bool sm2_is_OpenSSL_ASN1_Format(const std::string_view& source) {
            const unsigned char* in = (const unsigned char*)source.data();
            CAMEL_SM2_Ciphertext* a = nullptr;
            const unsigned char* p = in;
            a = d2i_CAMEL_SM2_Ciphertext(nullptr, &p, source.size());
            if (a == nullptr) {
                return false;
            }
            CAMEL_SM2_Ciphertext_free(a);
            return true;
        }

        inline void freeCiphertextStructInnerData(const CAMEL_SM2_Ciphertext& ctx) {
            if (ctx.C1x != nullptr) {
                BN_free(ctx.C1x);
            }
            if (ctx.C1y != nullptr) {
                BN_free(ctx.C1y);
            }
            if (ctx.C2 != nullptr) {
                ASN1_OCTET_STRING_free(ctx.C2);
            }

            if (ctx.C3 != nullptr) {
                ASN1_OCTET_STRING_free(ctx.C3);
            }
        };

        /**
         *  JAVA的bouncycastle中SM2Engine输出结构为：
         *   switch (this.mode.ordinal()) {
         *            case 1:
         *                return Arrays.concatenate(c1, c3, c2);
         *            default:
          *               return Arrays.concatenate(c1, c2, c3);
        *   c1[64]  + c2 + c3[32]
        *   对于输出 c1 + c3 + c2 的情况，可参考这个代码根据场景进行实现。
         */
        std::string sm2_java_c1_c2_c3_to_OpenSSL_ASN1_Format(const std::string_view& javaData) {
            if (javaData.length() <= 96) {
                return  "";
            }
            std::string_view source = javaData;
            //非压缩格式标识符号 0x04 + 64位c1。  0x03 或者 0x02是压缩个暂时不支持
            //java中的格式实现可参考： ECPoint中的getEncoded方法
            if (javaData[0] == 0x04) {
                if (javaData.length() <= 97) {
                    return  "";
                }
                source = std::string_view(javaData.data() + 1, javaData.size() - 1);
            }
            CAMEL_SM2_Ciphertext ctx;
            ctx.C1x = nullptr;
            ctx.C1y = nullptr;
            ctx.C2 = nullptr;
            ctx.C3 = nullptr;

            const unsigned char* in = (const unsigned char*)source.data();
            ctx.C1x = BN_bin2bn(in, 32, nullptr);
            if (ctx.C1x == nullptr) {
                std::cerr << "java_c1_c2_c3_to_OpenSSL_ASN1_Format BN_bin2bn ctx.C1x error" << std::endl;
                freeCiphertextStructInnerData(ctx);
                return "";
            }
            ctx.C1y = BN_bin2bn(in + 32, 32, nullptr);
            if (ctx.C1y == nullptr) {
                std::cerr << "java_c1_c2_c3_to_OpenSSL_ASN1_Format BN_bin2bn ctx.C1y error" << std::endl;
                freeCiphertextStructInnerData(ctx);
                return "";
            }
            ctx.C2 = ASN1_OCTET_STRING_new();
            if (ctx.C2 == nullptr) {
                std::cerr << "java_c1_c2_c3_to_OpenSSL_ASN1_Format ASN1_OCTET_STRING_new ctx.C2 error" << std::endl;
                freeCiphertextStructInnerData(ctx);
                return "";
            }
            if (!ASN1_OCTET_STRING_set(ctx.C2, in + 64, source.size() - 96)) {
                std::cerr << "java_c1_c2_c3_to_OpenSSL_ASN1_Format ASN1_OCTET_STRING_set ctx.C2 error" << std::endl;
                freeCiphertextStructInnerData(ctx);
                return "";
            }

            ctx.C3 = ASN1_OCTET_STRING_new();
            if (ctx.C3 == nullptr) {
                std::cerr << "java_c1_c2_c3_to_OpenSSL_ASN1_Format ASN1_OCTET_STRING_new ctx.C3 error" << std::endl;
                freeCiphertextStructInnerData(ctx);
                return "";
            }
            if (!ASN1_OCTET_STRING_set(ctx.C3, in + (source.size() - 32), 32)) {
                std::cerr << "java_c1_c2_c3_to_OpenSSL_ASN1_Format ASN1_OCTET_STRING_set ctx.C3 error" << std::endl;
                freeCiphertextStructInnerData(ctx);
                return "";
            }

            std::string buffer(source.size() + 512, '\0');
            unsigned char* out = (unsigned char*)buffer.data();
            int outlen = i2d_CAMEL_SM2_Ciphertext(&ctx, &out);
            buffer.resize(outlen);

            freeCiphertextStructInnerData(ctx);

            return buffer;
        }

        std::string sm2_java_c1_c3_c2_to_OpenSSL_ASN1_Format(const std::string_view& javaData) {
            if (javaData.length() <= 96) {
                return  "";
            }
            std::string_view source = javaData;
            //非压缩格式标识符号 0x04 + 64位c1。  0x03 或者 0x02是压缩个暂时不支持
            //java中的格式实现可参考： ECPoint中的getEncoded方法
            if (javaData[0] == 0x04) {
                if (javaData.length() <= 97) {
                    return  "";
                }
                source = std::string_view(javaData.data() + 1, javaData.size() - 1);
            }
            CAMEL_SM2_Ciphertext ctx;
            ctx.C1x = nullptr;
            ctx.C1y = nullptr;
            ctx.C2 = nullptr;
            ctx.C3 = nullptr;

            const unsigned char* in = (const unsigned char*)source.data();
            ctx.C1x = BN_bin2bn(in, 32, nullptr);
            if (ctx.C1x == nullptr) {
                std::cerr << "java_c1_c3_c2_to_OpenSSL_ASN1_Format BN_bin2bn ctx.C1x error" << std::endl;
                freeCiphertextStructInnerData(ctx);
                return "";
            }
            ctx.C1y = BN_bin2bn(in + 32, 32, nullptr);
            if (ctx.C1y == nullptr) {
                std::cerr << "java_c1_c3_c2_to_OpenSSL_ASN1_Format BN_bin2bn ctx.C1y error" << std::endl;
                freeCiphertextStructInnerData(ctx);
                return "";
            }
            ctx.C3 = ASN1_OCTET_STRING_new();
            if (ctx.C3 == nullptr) {
                std::cerr << "java_c1_c3_c2_to_OpenSSL_ASN1_Format ASN1_OCTET_STRING_new ctx.C3 error" << std::endl;
                freeCiphertextStructInnerData(ctx);
                return "";
            }
            if (!ASN1_OCTET_STRING_set(ctx.C3, in + 64, 32)) {
                std::cerr << "java_c1_c3_c2_to_OpenSSL_ASN1_Format ASN1_OCTET_STRING_set ctx.C3 error" << std::endl;
                freeCiphertextStructInnerData(ctx);
                return "";
            }

            ctx.C2 = ASN1_OCTET_STRING_new();
            if (ctx.C2 == nullptr) {
                std::cerr << "java_c1_c3_c2_to_OpenSSL_ASN1_Format ASN1_OCTET_STRING_new ctx.C2 error" << std::endl;
                freeCiphertextStructInnerData(ctx);
                return "";
            }
            if (!ASN1_OCTET_STRING_set(ctx.C2, in + 64 +  32, (source.size() - 32 - 64))) {
                std::cerr << "java_c1_c3_c2_to_OpenSSL_ASN1_Format ASN1_OCTET_STRING_set ctx.C2 error" << std::endl;
                freeCiphertextStructInnerData(ctx);
                return "";
            }

            std::string ans1Buffer(source.size() + 512, '\0');
            unsigned char* out = (unsigned char*)ans1Buffer.data();
            int outlen = i2d_CAMEL_SM2_Ciphertext(&ctx, &out);
            ans1Buffer.resize(outlen);

            freeCiphertextStructInnerData(ctx);

            return ans1Buffer;
        }

        /**
        *  JAVA的bouncycastle中SM2Engine输出结构为：
        *   switch (this.mode.ordinal()) {
        *            case 1:
        *                return Arrays.concatenate(c1, c3, c2);
        *            default:
         *               return Arrays.concatenate(c1, c2, c3);
       *   c1[64]  + c2 + c3[32]
       *   把ASN1转换为非压缩 compressFlag + c1[64]  + c2 + c3[32]格式的数据。
        */
        std::string sm2_ASN1_to_java_c1_c2_c3_Format(const std::string_view& ans1Data) {
            if (ans1Data.size() <= 96) {
                std::cerr << "sm2_ASN1_to_java_c1_c2_c3_Format ans1Data.size() illegal" << std::endl;
                return "";
            }
            const unsigned char* in = (const unsigned char*)ans1Data.data();
            CAMEL_SM2_Ciphertext* ctx = nullptr;
            const unsigned char* p = in;
            ctx = d2i_CAMEL_SM2_Ciphertext(nullptr, &p, ans1Data.size());
            if (ctx == nullptr) {
                std::cerr << "sm2_ASN1_to_java_c1_c2_c3_Format d2i_CAMEL_SM2_Ciphertext error" << std::endl;
                return "";
            }
            if (ctx->C3->length != 32) {
                std::cerr << "sm2_ASN1_to_java_c1_c2_c3_Format ctx->C3->length length illegal" << std::endl;
                CAMEL_SM2_Ciphertext_free(ctx);
                return "";
            }
            int totalLength = 1 + 64 + ctx->C2->length + ctx->C3->length;
            std::string buffer(totalLength, '\0');

            unsigned char* out = (unsigned char*)buffer.data();
            *out = 0x04; //none compress flag
            out += 1;
            if (BN_bn2binpad(ctx->C1x, out, 32) != 32) {
                std::cerr << "sm2_ASN1_to_java_c1_c2_c3_Format BN_bn2binpad failed C1x" << std::endl;
                CAMEL_SM2_Ciphertext_free(ctx);
                return "";
            }
            out += 32;
            if (BN_bn2binpad(ctx->C1y, out, 32) != 32) {
                std::cerr << "sm2_ASN1_to_java_c1_c2_c3_Format BN_bn2binpad failed C1y" << std::endl;
                CAMEL_SM2_Ciphertext_free(ctx);
                return "";
            }
            out += 32;
            std::memcpy(out, ctx->C2->data, ctx->C2->length);
            out += ctx->C2->length;
            std::memcpy(out, ctx->C3->data, ctx->C3->length); //c3 length is 32




            CAMEL_SM2_Ciphertext_free(ctx);

            return buffer;
        }


        // 把ASN1转换为非压缩 compressFlag + c1[64] + c3[32]  + c2 格式的数据。
        std::string sm2_ASN1_to_java_c1_c3_c2_Format(const std::string_view& ans1Data) {
            if (ans1Data.size() <= 96) {
                std::cerr << "sm2_ASN1_to_java_c1_c3_c2_Format ans1Data.size() illegal" << std::endl;
                return "";
            }
            const unsigned char* in = (const unsigned char*)ans1Data.data();
            CAMEL_SM2_Ciphertext* ctx = nullptr;
            const unsigned char* p = in;
            ctx = d2i_CAMEL_SM2_Ciphertext(nullptr, &p, ans1Data.size());
            if (ctx == nullptr) {
                std::cerr << "sm2_ASN1_to_java_c1_c3_c2_Format d2i_CAMEL_SM2_Ciphertext error" << std::endl;
                return "";
            }
            if (ctx->C3->length != 32) {
                std::cerr << "sm2_ASN1_to_java_c1_c3_c2_Format ctx->C3->length length illegal" << std::endl;
                CAMEL_SM2_Ciphertext_free(ctx);
                return "";
            }
            int totalLength = 1 + 64 + ctx->C2->length + ctx->C3->length;
            std::string buffer(totalLength, '\0');

            unsigned char* out = (unsigned char*)buffer.data();
            *out++ = 0x04; //none compress flag
            if (BN_bn2binpad(ctx->C1x, out, 32) != 32) {
                std::cerr << "sm2_ASN1_to_java_c1_c3_c2_Format BN_bn2binpad failed C1x" << std::endl;
                CAMEL_SM2_Ciphertext_free(ctx);
                return "";
            }
            out += 32;
            if (BN_bn2binpad(ctx->C1y, out, 32) != 32) {
                std::cerr << "sm2_ASN1_to_java_c1_c3_c2_Format BN_bn2binpad failed C1y" << std::endl;
                CAMEL_SM2_Ciphertext_free(ctx);
                return "";
            }
            out += 32;
            std::memcpy(out, ctx->C3->data, ctx->C3->length); //c3 length is 32
            out += ctx->C3->length;
            std::memcpy(out, ctx->C2->data, ctx->C2->length);

            CAMEL_SM2_Ciphertext_free(ctx);

            return buffer;
        }
    }
}

namespace camel {
    namespace crypto {

        SM2PublicKeyEncryptor::SM2PublicKeyEncryptor(const std::string_view &publicKey,
            const std::string_view &format,
            const std::string_view& dataModeFlag) {
            this->format = format;
            this->dataModeFlag = dataModeFlag;
            this->publicKey = publicKey;
            this->externalEvpKey = nullptr;
            std::transform(this->dataModeFlag.begin(), this->dataModeFlag.end(), this->dataModeFlag.begin(), ::toupper);
        }

        std::string SM2PublicKeyEncryptor::encrypt(const std::string_view &plainText) const {
            if (plainText.empty()) {
                return "";
            }
            EVP_PKEY* evpKey = externalEvpKey;
            if (evpKey == nullptr) {
                evpKey = SM2PublicKeyFrom(publicKey, format);
            }
            if (evpKey == nullptr) {
                std::cerr << "SM2PublicKeyEncryptor::encrypt() Failed to create EVP_PKEY_CTX_new " << std::endl;
                printOpenSSLError();
                return "";
            }
            SM2EvpKeyGuard evpKeyGuard(evpKey, externalEvpKey == nullptr);

            EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_pkey(nullptr, evpKey, nullptr);
            if (ctx == nullptr) {
                std::cerr << "SM2PublicKeyEncryptor::encrypt() Failed to create EVP_PKEY_CTX_new_from_pkey" << std::endl;
                printOpenSSLError();
                return "";
            }

            if (!sm2ConfigEncryptParams(evpKey, ctx, dataModeFlag)) {
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
                std::cerr << "SM2PublicKeyEncryptor::encrypt() Failed to EVP_PKEY_encrypt " << std::endl;
                printOpenSSLError();
                EVP_PKEY_CTX_free(ctx);
                return "";
            }
            totalLength += outlen;
            buffer.resize(totalLength);
            EVP_PKEY_CTX_free(ctx);

            if (dataModeFlag == "C1C2C3") {
               return sm2_ASN1_to_java_c1_c2_c3_Format(buffer);
            }

            if (dataModeFlag == "C1C3C2") {
                return sm2_ASN1_to_java_c1_c3_c2_Format(buffer);
            }

            return buffer;
        }


        std::string SM2PublicKeyEncryptor::encryptToBase64(const std::string_view &plainText) const {
            return base64_encode(encrypt(plainText));
        }

        std::string SM2PublicKeyEncryptor::encryptToHex(const std::string_view &plainText) const {
            return hex_encode(encrypt(plainText));
        }
    }
}


namespace camel {
    namespace crypto {
          SM2PrivateKeyDecryptor::SM2PrivateKeyDecryptor(const std::string_view& privateKey,
                          const std::string_view& format,
                          const std::string_view& dataModeFlag) {
            this->dataModeFlag = dataModeFlag;
            this->format = format;
            this->privateKey = privateKey;
            this->externalEvpKey = nullptr;
            std::transform(this->dataModeFlag.begin(), this->dataModeFlag.end(), this->dataModeFlag.begin(), ::toupper);
          }

          std::string SM2PrivateKeyDecryptor::decrypt(const std::string_view &sourceData) {
              if (sourceData.empty()) {
                  return "";
              }

              EVP_PKEY *evpKey = externalEvpKey;
              if (evpKey == nullptr) {
                  evpKey = SM2PrivateKeyFrom(privateKey, format);
              }
              if (evpKey == nullptr) {
                  return "";
              }
              SM2EvpKeyGuard evpKeyGuard(evpKey, externalEvpKey == nullptr);

              EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(evpKey, nullptr);

              if (ctx == nullptr) {
                  std::cerr << "SM2PrivateKeyDecryptor::decrypt() Failed to create EVP_PKEY_CTX_new " << std::endl;
                  printOpenSSLError();
                  return "";
              }

              if (!sm2ConfigDecryptParams(evpKey, ctx, dataModeFlag)) {
                  EVP_PKEY_CTX_free(ctx);
                  return "";
              }
              std::string_view ans1Data = sourceData;
              std::string ans1DataHoler;
              if (dataModeFlag == "C1C2C3") {
                  ans1DataHoler = sm2_java_c1_c2_c3_to_OpenSSL_ASN1_Format(sourceData);
                  ans1Data = ans1DataHoler;
              } else if (dataModeFlag == "C1C3C2") {
                  ans1DataHoler = sm2_java_c1_c3_c2_to_OpenSSL_ASN1_Format(sourceData);
                  ans1Data = ans1DataHoler;
              } else if (!sm2_is_OpenSSL_ASN1_Format(sourceData)) {
                  ans1DataHoler = sm2_java_c1_c2_c3_to_OpenSSL_ASN1_Format(sourceData);
                  ans1Data = ans1DataHoler;
             }

              std::string buffer;
              int bigBufferSize = ans1Data.size();
              buffer.resize(std::max(bigBufferSize, 1024));


              unsigned char *in = (unsigned char *) ans1Data.data();
              unsigned char *out = (unsigned char *) buffer.data();
              size_t totalLength = 0;
              size_t outlen = buffer.size() - totalLength;
              size_t inlen = ans1Data.size();
              if (EVP_PKEY_decrypt(ctx, out, &outlen, in, inlen) <= 0) {
                  std::cerr << "SM2PrivateKeyDecryptor::decrypt() Failed to EVP_PKEY_decrypt " << std::endl;
                  printOpenSSLError();
                  EVP_PKEY_CTX_free(ctx);
                  return "";
              }
              totalLength += outlen;

              buffer.resize(totalLength);

              EVP_PKEY_CTX_free(ctx);

              return buffer;
          }

        std::string SM2PrivateKeyDecryptor::decryptFromHex(const std::string_view &encryptedText){
            std::string data = hex_decode(encryptedText);
            return decrypt(data);
        }

        std::string SM2PrivateKeyDecryptor::decryptFromBase64(const std::string_view &encryptedText) {
            std::string data = base64_decode_url_safe(encryptedText);
            return decrypt(data);
        }
    }
}