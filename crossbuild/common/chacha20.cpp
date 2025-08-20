//
// Created by baojian on 2025/8/20.
//

#include "chacha20.h"

#include <iostream>

#include "base64.h"
#include "config.h"
#include "hex.h"
#include "openssl/core_names.h"
#include "openssl/rand.h"

namespace camel {
    namespace crypto {

        ChaCha20KeyGenerator::ChaCha20KeyGenerator() {
            this->secretKey.resize(256/8);
            unsigned char * buffer = (unsigned char *)secretKey.data();
            if (RAND_priv_bytes(buffer, secretKey.size()) != 1) {
                std::cerr << "ChaCha20KeyGenerator::ChaCha20KeyGenerator() RAND_priv_bytes() failed" << std::endl;
                printOpenSSLError();
                secretKey = "";
            }
        }

        std::string ChaCha20KeyGenerator::getKey() {
            return secretKey;
        }

        std::string ChaCha20KeyGenerator::getHexKey() {
            return hex_encode(secretKey);
        }

        std::string ChaCha20KeyGenerator::getBase64Key() {
            return base64_encode(secretKey);
        }

    }
}

namespace camel {
    namespace crypto {
        inline bool chaCha20AlgorithmHas(const std::string& algorithm, std::string_view target) {
            return algorithm.find(target) != std::string::npos;
        }

        std::string getChaCha20Key(const std::string_view& chaCha20Key, const std::string_view& format) {
            if (format == "base64") {
                return base64_decode(chaCha20Key);
            } else if (format == "hex") {
                return hex_decode(chaCha20Key);
            }  else if (format == "binary" || format == "raw") {
                return std::string(chaCha20Key);
            } else {
                return std::string(chaCha20Key);
            }
        }


         std::string chaCha20_encrypt(const std::string& algorithm, const std::string& secretKey, const std::string_view &plainData) {
            EVP_CIPHER_CTX *ctx = nullptr;
            EVP_CIPHER *cipher = nullptr;
            ctx = EVP_CIPHER_CTX_new();
            if (ctx == nullptr) {
                std::cerr << "aes_normal_encrypt EVP_CIPHER_CTX_new() failed" << std::endl;
                printOpenSSLError();
                return "";
            }
            std::string algorithmName = "ChaCha20";
            if (chaCha20AlgorithmHas(algorithm, "Poly1305")) {
                algorithmName = "ChaCha20-Poly1305";
            }
            cipher = EVP_CIPHER_fetch(nullptr, algorithmName.data(), nullptr);
            if (cipher == nullptr) {
                std::cerr << "chaCha20_encrypt EVP_CIPHER_fetch() failed" << std::endl;
                printOpenSSLError();
                EVP_CIPHER_CTX_free(ctx);
                return "";
            }

            std::string combineBuffer; // iv + buffer + tag
            combineBuffer.resize(std::max((int)plainData.size()*2 + 64, 512));
            size_t nonce_iv_len = 12;  //标准12位 nonce iv
            {
                //标准12位 nonce iv
                unsigned char* iv = (unsigned char* )combineBuffer.data();
                if (RAND_bytes(iv, nonce_iv_len) != 1) {
                    std::cerr << "achaCha20_encrypt RAND_bytes() failed" << std::endl;
                    printOpenSSLError();
                    EVP_CIPHER_free(cipher);
                    EVP_CIPHER_CTX_free(ctx);
                    return "";
                }

                OSSL_PARAM params[] = {
                    OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_IVLEN,
                                            &nonce_iv_len),
                    OSSL_PARAM_END
                };
                const unsigned char *key = (const unsigned char *)secretKey.data();
                if (!EVP_EncryptInit_ex2(ctx, cipher, key, iv, params)) {
                    std::cerr << "chaCha20_encrypt EVP_EncryptInit_ex2() failed" << std::endl;
                    printOpenSSLError();
                    EVP_CIPHER_free(cipher);
                    EVP_CIPHER_CTX_free(ctx);
                    return "";
                }
            }

            const unsigned char *in = (const unsigned char *)(plainData.data());
            int inl = plainData.size();
            unsigned char *out = (unsigned char *)(combineBuffer.data() + nonce_iv_len);
            int outl = combineBuffer.size() - nonce_iv_len;
            int totalLen = nonce_iv_len;
            if (!EVP_EncryptUpdate(ctx, out, &outl, in, inl)) {
                std::cerr << "chaCha20_encrypt EVP_EncryptUpdate() failed" << std::endl;
                printOpenSSLError();
                EVP_CIPHER_free(cipher);
                EVP_CIPHER_CTX_free(ctx);
                return "";
            }
            totalLen += outl;
            int tempLen = combineBuffer.size() - nonce_iv_len - outl;
            if (!EVP_EncryptFinal_ex(ctx, out + outl, &tempLen)) {
                std::cerr << "chaCha20_encrypt EVP_EncryptFinal_ex() failed" << std::endl;
                printOpenSSLError();
                EVP_CIPHER_free(cipher);
                EVP_CIPHER_CTX_free(ctx);
                return "";
            }
            totalLen += tempLen;
            combineBuffer.resize(totalLen);
            EVP_CIPHER_free(cipher);
            EVP_CIPHER_CTX_free(ctx);
            return combineBuffer;
        }

        std::string chaCha20_decrypt(const std::string& algorithm, const std::string& secretKey, const std::string_view &encryptData) {
            EVP_CIPHER_CTX *ctx = nullptr;
            EVP_CIPHER *cipher = nullptr;
            ctx = EVP_CIPHER_CTX_new();
            if (ctx == nullptr) {
                std::cerr << "aes_normal_encrypt EVP_CIPHER_CTX_new() failed" << std::endl;
                printOpenSSLError();
                return "";
            }
            std::string algorithmName = "ChaCha20";
            if (chaCha20AlgorithmHas(algorithm, "Poly1305")) {
                algorithmName = "ChaCha20-Poly1305";
            }
            cipher = EVP_CIPHER_fetch(nullptr, algorithmName.data(), nullptr);
            if (cipher == nullptr) {
                std::cerr << "chaCha20_encrypt EVP_CIPHER_fetch() failed" << std::endl;
                printOpenSSLError();
                EVP_CIPHER_CTX_free(ctx);
                return "";
            }
            size_t nonce_iv_len = 12;  //标准12位 nonce iv
            {
                if (encryptData.size() <= nonce_iv_len) {
                    std::cerr << "aes_normal_decrypt illegal, encryptData too short " << std::endl;
                    return "";
                }
                OSSL_PARAM params[] = {
                    OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_IVLEN,
                                            &nonce_iv_len),
                    OSSL_PARAM_END
                };
                const unsigned char *key = (const unsigned char *)secretKey.data();
                const unsigned char *iv = (const unsigned char *)encryptData.data();
                if (!EVP_DecryptInit_ex2(ctx, cipher, key, iv, params)) {
                    std::cerr << "aes_normal_decrypt EVP_DecryptInit_ex2() failed" << std::endl;
                    printOpenSSLError();
                    EVP_CIPHER_free(cipher);
                    EVP_CIPHER_CTX_free(ctx);
                    return "";
                }
            }

            std::string buffer;
            buffer.resize(std::max((int)encryptData.size() + 8, 512));
            const unsigned char *in = (const unsigned char *)(encryptData.data() + nonce_iv_len);
            int inl = encryptData.size() - nonce_iv_len;
            unsigned char *out = (unsigned char *)buffer.data();
            int outl = buffer.size();
            int totalLen = 0;
            if (!EVP_DecryptUpdate(ctx, out, &outl, in, inl)) {
                std::cerr << "aes_normal_decrypt EVP_DecryptUpdate() failed" << std::endl;
                printOpenSSLError();
                EVP_CIPHER_free(cipher);
                EVP_CIPHER_CTX_free(ctx);
                return "";
            }
            totalLen += outl;
            int tempLen = buffer.size() - outl;
            if (!EVP_DecryptFinal_ex(ctx, out + outl, &tempLen)) {
                std::cerr << "aes_normal_decrypt EVP_DecryptFinal_ex() failed" << std::endl;
                printOpenSSLError();
                EVP_CIPHER_free(cipher);
                EVP_CIPHER_CTX_free(ctx);
                return "";
            }
            totalLen += tempLen;
            buffer.resize(totalLen);
            EVP_CIPHER_free(cipher);
            EVP_CIPHER_CTX_free(ctx);
            return buffer;
        }


    }
}


namespace camel {
    namespace crypto {
        ChaCha20Encryptor::ChaCha20Encryptor(const std::string_view& algorithm, const std::string_view& secret, const std::string_view& format) {
            this->algorithm = algorithm;
            this->secretKey = getChaCha20Key(secret, format);
        }

        std::string ChaCha20Encryptor::encrypt(const std::string_view &plainText) const {
            return chaCha20_encrypt(algorithm, secretKey, plainText);
        }

        std::string ChaCha20Encryptor::encryptToHex(const std::string_view &plainText) const {
            return hex_encode(encrypt(plainText));
        }


        std::string ChaCha20Encryptor::encryptToBase64(const std::string_view &plainText) const {
            return base64_encode(encrypt(plainText));
        }

        std::string ChaCha20Encryptor::encryptWithAAD(const std::string_view &plainText, const std::string_view &aad) const {
            std::cerr << "ChaCha20Encryptor::encryptWithAAD() not supported algorithm " << algorithm << std::endl;
            return "";
        }

        std::string ChaCha20Encryptor::encryptToHexWithAAD(const std::string_view &plainText, const std::string_view &aad) const {
            return hex_encode(encryptWithAAD(plainText, aad));
        }

        std::string ChaCha20Encryptor::encryptToBase64WithAAD(const std::string_view &plainText, const std::string_view &aad) const {
            return base64_encode(encryptWithAAD(plainText, aad));
        }

    }
}

namespace camel {
    namespace crypto {}
}
