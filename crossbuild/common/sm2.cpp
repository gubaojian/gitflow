//
// Created by efurture on 25-8-19.
//

#include "sm2.h"

#include <iostream>

#include "base64.h"
#include "config.h"
#include "hex.h"
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


        bool sm2ConfigEncryptParams(EVP_PKEY* evpKey, EVP_PKEY_CTX *ctx, const std::string& algorithm) {
            OSSL_PARAM params[] = {
             OSSL_PARAM_END
            };
            if (EVP_PKEY_encrypt_init_ex(ctx, params) <= 0) {
                std::cerr << "sm2ConfigEncryptParams Failed to EVP_PKEY_CTX_set_params" << std::endl;
                printOpenSSLError();
                return false;
            }
            return true;
            //std::cerr << "sm2ConfigEncryptParams  unsupported mode " << algorithm << std::endl;
            //return false;
        }

        bool sm2ConfigDecryptParams(EVP_PKEY* evpKey, EVP_PKEY_CTX *ctx, const std::string& algorithm) {
            OSSL_PARAM params[] = {
                OSSL_PARAM_END
               };
            if (EVP_PKEY_decrypt_init_ex(ctx, params) <= 0) {
                std::cerr << "sm2ConfigDecryptParams Failed to EVP_PKEY_CTX_set_params" << std::endl;
                printOpenSSLError();
                return false;
            }
            return true;
            //std::cerr << "sm2ConfigDecryptParams unsupported mode " << algorithm << std::endl;
            //return false;
        }
    }
}

namespace camel {
    namespace crypto {

        SM2PublicKeyEncryptor::SM2PublicKeyEncryptor(const std::string_view &publicKey,
            const std::string_view &format,
            const std::string_view& algorithm) {
            this->format = format;
            this->algorithm = algorithm;
            this->publicKey = publicKey;
            this->externalEvpKey = nullptr;
            std::transform(this->algorithm.begin(), this->algorithm.end(), this->algorithm.begin(), ::toupper);
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
                std::cerr << "SM2PublicKeyEncryptor::decrypt() Failed to create EVP_PKEY_CTX_new " << std::endl;
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

            if (!sm2ConfigEncryptParams(evpKey, ctx, algorithm)) {
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
                  const std::string_view& paddings) {
            this->algorithm = paddings;
            this->format = format;
            this->privateKey = privateKey;
            this->externalEvpKey = nullptr;
        }

  std::string SM2PrivateKeyDecryptor::decrypt(const std::string_view &encryptedData) {
      if (encryptedData.empty()) {
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

      if (!sm2ConfigDecryptParams(evpKey, ctx, algorithm)) {
          EVP_PKEY_CTX_free(ctx);
          return "";
      }

      std::string buffer;
      int bigBufferSize = encryptedData.size();
      buffer.resize(std::max(bigBufferSize, 1024));


      unsigned char *in = (unsigned char *) encryptedData.data();
      unsigned char *out = (unsigned char *) buffer.data();
      size_t totalLength = 0;
      size_t outlen = buffer.size() - totalLength;
      size_t inlen = encryptedData.size();
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