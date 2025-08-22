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

        std::string getChaCha20Poly1305Key(const std::string_view& chaCha20Key, const std::string_view& format) {
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

        std::string chaCha20_decrypt(const std::string& secretKey, const std::string_view &encryptData) {
            EVP_CIPHER_CTX *ctx = nullptr;
            EVP_CIPHER *cipher = nullptr;
            ctx = EVP_CIPHER_CTX_new();
            if (ctx == nullptr) {
                std::cerr << "chaCha20_decrypt EVP_CIPHER_CTX_new() failed" << std::endl;
                printOpenSSLError();
                return "";
            }
            std::string algorithmName = "ChaCha20";
            cipher = EVP_CIPHER_fetch(nullptr, algorithmName.data(), nullptr);
            if (cipher == nullptr) {
                std::cerr << "chaCha20_encrypt EVP_CIPHER_fetch() failed" << std::endl;
                printOpenSSLError();
                EVP_CIPHER_CTX_free(ctx);
                return "";
            }
            /**
             * The ChaCha20 stream cipher. The key length is 256 bits, the IV is 128 bits long.
             * The first 64 bits consists of a counter in little-endian order followed by a 64 bit nonce.
             * 标准12位 nonce iv，openssl中的实现是16位， https://docs.openssl.org/3.1/man3/EVP_chacha20/
             * https://github.com/openssl/openssl/issues/21095
             */
            size_t nonce_iv_len = 16;
            {
                if (encryptData.size() <= nonce_iv_len) {
                    std::cerr << "chaCha20_decrypt illegal, encryptData too short " << std::endl;
                    return "";
                }
                OSSL_PARAM params[] = {
                    OSSL_PARAM_END
                };
                const unsigned char *key = (const unsigned char *)secretKey.data();
                const unsigned char *iv = (const unsigned char *)encryptData.data();
                if (!EVP_DecryptInit_ex2(ctx, cipher, key, iv, params)) {
                    std::cerr << "chaCha20_decrypt EVP_DecryptInit_ex2() failed" << std::endl;
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
                std::cerr << "chaCha20_decrypt EVP_DecryptUpdate() failed" << std::endl;
                printOpenSSLError();
                EVP_CIPHER_free(cipher);
                EVP_CIPHER_CTX_free(ctx);
                return "";
            }
            totalLen += outl;
            int tempLen = buffer.size() - outl;
            if (!EVP_DecryptFinal_ex(ctx, out + outl, &tempLen)) {
                std::cerr << "chaCha20_decrypt EVP_DecryptFinal_ex() failed" << std::endl;
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

         std::string chaCha20_encrypt(const std::string& secretKey, const std::string_view &plainData) {
            EVP_CIPHER_CTX *ctx = nullptr;
            EVP_CIPHER *cipher = nullptr;
            ctx = EVP_CIPHER_CTX_new();
            if (ctx == nullptr) {
                std::cerr << "chaCha20_encrypt EVP_CIPHER_CTX_new() failed" << std::endl;
                printOpenSSLError();
                return "";
            }
            std::string algorithmName = "ChaCha20";
            cipher = EVP_CIPHER_fetch(nullptr, algorithmName.data(), nullptr);
            if (cipher == nullptr) {
                std::cerr << "chaCha20_encrypt EVP_CIPHER_fetch() failed" << std::endl;
                printOpenSSLError();
                EVP_CIPHER_CTX_free(ctx);
                return "";
            }

            std::string combineBuffer; // iv + buffer + tag
            combineBuffer.resize(std::max((int)plainData.size()*2 + 64, 512));
            /**
            * The ChaCha20 stream cipher. The key length is 256 bits, the IV is 128 bits long.
            * The first 64 bits consists of a counter in little-endian order followed by a 64 bit nonce.
            * 标准12位 nonce iv，openssl中的实现是16位， https://docs.openssl.org/3.1/man3/EVP_chacha20/
            * https://github.com/openssl/openssl/issues/21095
            */
            size_t nonce_iv_len = 16;
            {
                //RFC 7539 Java等其它实现都是 标准12位 nonce iv
                unsigned char* iv = (unsigned char* )combineBuffer.data();
                //前4位默认位0，生成12位iv，和Java 12位对应
                std::memset(iv, 0, 4);
                if (RAND_bytes(iv + 4, 12) != 1) {
                    std::cerr << "achaCha20_encrypt RAND_bytes() failed" << std::endl;
                    printOpenSSLError();
                    EVP_CIPHER_free(cipher);
                    EVP_CIPHER_CTX_free(ctx);
                    return "";
                }

                OSSL_PARAM params[] = {
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

    }
}


namespace camel {
    namespace crypto {
        ChaCha20Encryptor::ChaCha20Encryptor(const std::string_view& secret, const std::string_view& format) {
            this->secretKey = getChaCha20Key(secret, format);
        }

        std::string ChaCha20Encryptor::encrypt(const std::string_view &plainText) const {
            return chaCha20_encrypt(secretKey, plainText);
        }

        std::string ChaCha20Encryptor::encryptToHex(const std::string_view &plainText) const {
            return hex_encode(encrypt(plainText));
        }


        std::string ChaCha20Encryptor::encryptToBase64(const std::string_view &plainText) const {
            return base64_encode(encrypt(plainText));
        }
    }
}

namespace camel {
    namespace crypto {
         ChaCha20Decryptor::ChaCha20Decryptor(const std::string_view &secret, const std::string_view &format) {
             this->secretKey = getChaCha20Key(secret, format);
        }


        std::string ChaCha20Decryptor::decrypt(const std::string_view &encryptedData) const {
             return chaCha20_decrypt(secretKey, encryptedData);
        }

        std::string ChaCha20Decryptor::decryptFromHex(const std::string_view &hexEncryptedText) const {
            return decrypt(hex_decode(hexEncryptedText));
        }

        std::string ChaCha20Decryptor::decryptFromBase64(const std::string_view &base64EncryptedText) const {
            return decrypt(base64_decode(base64EncryptedText));
        }
    }
}


namespace camel {
    namespace crypto {
           std::string chaCha20Poly1305_encrypt(
            const std::string& secretKey,
            const std::string_view &plainData,
            const std::string_view &aad) {
            if (secretKey.size() != 32) {
                std::cerr << "chaCha20Poly1305_encrypt secretKey size invalid " << std::endl;
                return "";
            }

            int poly1305_nonce_iv_len = 12; // chaCha20Poly1305模式的once
            int poly1305_tag_len = 16; // chaCha20Poly1305 的tag

            EVP_CIPHER_CTX *ctx = nullptr;
            EVP_CIPHER *cipher = nullptr;
            ctx = EVP_CIPHER_CTX_new();
            if (ctx == nullptr) {
                std::cerr << "chaCha20Poly1305_encrypt EVP_CIPHER_CTX_new() failed" << std::endl;
                printOpenSSLError();
                return "";
            }
            std::string algorithmName = "ChaCha20-Poly1305";

            cipher = EVP_CIPHER_fetch(nullptr, algorithmName.data(), nullptr);
            if (cipher == nullptr) {
                std::cerr << "chaCha20Poly1305_encrypt EVP_CIPHER_fetch() failed" << std::endl;
                printOpenSSLError();
                EVP_CIPHER_CTX_free(ctx);
                return "";
            }
            std::string combineBuffer; // iv + buffer + tag
            combineBuffer.resize(std::max((int)plainData.size()*2 + 64, 512));

            { // init ctx
                unsigned char* iv = (unsigned char* )combineBuffer.data();
                if (RAND_bytes(iv, poly1305_nonce_iv_len) != 1) {
                    std::cerr << "chaCha20Poly1305_encrypt iv RAND_bytes() failed" << std::endl;
                    printOpenSSLError();
                    EVP_CIPHER_free(cipher);
                    EVP_CIPHER_CTX_free(ctx);
                    return "";
                }

                OSSL_PARAM params[] = {
                    OSSL_PARAM_construct_int(OSSL_CIPHER_PARAM_AEAD_IVLEN,
                                            &poly1305_nonce_iv_len),
                    OSSL_PARAM_construct_int(OSSL_CIPHER_PARAM_AEAD_TAGLEN,
                                           &poly1305_tag_len),
                    OSSL_PARAM_END
                };
                const unsigned char *key = (const unsigned char *)secretKey.data();
                /*
                 * Initialise encrypt operation with the cipher & mode,
                 * nonce/iv length and tag length parameters.
                 */
                if (!EVP_EncryptInit_ex2(ctx, cipher, nullptr, nullptr, params)) {
                    std::cerr << "chaCha20Poly1305_encrypt EVP_EncryptInit_ex2() failed" << std::endl;
                    printOpenSSLError();
                    EVP_CIPHER_free(cipher);
                    EVP_CIPHER_CTX_free(ctx);
                    return "";
                }
                // 分两步初始化，参考解密
                /* Initialise key and nonce/iv */
                if (!EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) {
                    std::cerr << "chaCha20Poly1305_encrypt EVP_EncryptInit_ex() failed" << std::endl;
                    printOpenSSLError();
                    EVP_CIPHER_free(cipher);
                    EVP_CIPHER_CTX_free(ctx);
                    return "";
                }
            }


            int ivLength = EVP_CIPHER_get_iv_length(cipher);
            if (ivLength != poly1305_nonce_iv_len) {
                std::cerr << "chaCha20Poly1305_encrypt Invalid IV length: must be 12 bytes" << std::endl;
                EVP_CIPHER_free(cipher);
                EVP_CIPHER_CTX_free(ctx);
                return "";
            }

            if (!aad.empty()) {
                int outlen;
                const unsigned char *aadIn = (const unsigned char *)aad.data();
                if (!EVP_EncryptUpdate(ctx, NULL, &outlen, aadIn, aad.size())) {
                    std::cerr << "chaCha20Poly1305_encrypt EVP_EncryptUpdate() aad failed" << std::endl;
                    EVP_CIPHER_free(cipher);
                    EVP_CIPHER_CTX_free(ctx);
                    return "";
                }
            }

            const unsigned char *in = (const unsigned char *)(plainData.data());
            int inl = plainData.size();
            unsigned char *out = (unsigned char *) combineBuffer.data() + poly1305_nonce_iv_len;
            int outl = combineBuffer.size() - poly1305_nonce_iv_len - poly1305_tag_len;
            int totalLen = poly1305_nonce_iv_len + poly1305_tag_len;
            if (!EVP_EncryptUpdate(ctx, out, &outl, in, inl)) {
                std::cerr << "chaCha20Poly1305_encrypt EVP_EncryptUpdate() failed" << std::endl;
                printOpenSSLError();
                EVP_CIPHER_free(cipher);
                EVP_CIPHER_CTX_free(ctx);
                return "";
            }
            totalLen += outl;

            int tempLen = combineBuffer.size() - poly1305_nonce_iv_len - poly1305_tag_len - outl;
            if (!EVP_EncryptFinal_ex(ctx, out + outl, &tempLen)) {
                std::cerr << "chaCha20Poly1305_encrypt EVP_EncryptFinal_ex() failed" << std::endl;
                printOpenSSLError();
                EVP_CIPHER_free(cipher);
                EVP_CIPHER_CTX_free(ctx);
                return "";
            }
            totalLen += tempLen;

            unsigned char* tag = (unsigned char*)(combineBuffer.data() + totalLen - poly1305_tag_len);
            OSSL_PARAM params[] = {
                OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, tag, poly1305_tag_len),
                OSSL_PARAM_END
            };
            if (!EVP_CIPHER_CTX_get_params(ctx, params)) {
                std::cerr << "chaCha20Poly1305_encrypt EVP_CIPHER_CTX_get_params() failed" << std::endl;
                printOpenSSLError();
                EVP_CIPHER_free(cipher);
                EVP_CIPHER_CTX_free(ctx);
                return "";
            }

            combineBuffer.resize(totalLen);
            EVP_CIPHER_free(cipher);
            EVP_CIPHER_CTX_free(ctx);
            return combineBuffer;
        }

        std::string chaCha20Poly1305_decrypt(   const std::string& secretKey, const std::string_view &encryptData, const std::string_view &aad) {

            if (secretKey.size() != 32) {
                std::cerr << "chaCha20Poly1305_decrypt secretKey size invalid" << std::endl;
                return "";
            }
            size_t poly1305_nonce_iv_len = 12; // poly1305 nonce 长度12
            size_t poly1305_tag_len = 16; // poly1305的tag 长度16
            if (encryptData.size() <= (poly1305_nonce_iv_len + poly1305_tag_len)) {
                std::cerr << "chaCha20Poly1305_decrypt illegal, encryptData too short " << std::endl;
                return "";
            }
            EVP_CIPHER_CTX *ctx = nullptr;
            EVP_CIPHER *cipher = nullptr;
            ctx = EVP_CIPHER_CTX_new();
            if (ctx == nullptr) {
                std::cerr << "chaCha20Poly1305_decrypt EVP_CIPHER_CTX_new() failed" << std::endl;
                printOpenSSLError();
                return "";
            }
            std::string algorithmName = "ChaCha20-Poly1305";

            cipher = EVP_CIPHER_fetch(nullptr, algorithmName.data(), nullptr);
            if (cipher == nullptr) {
                std::cerr << "chaCha20Poly1305_decrypt EVP_CIPHER_fetch() failed" << std::endl;
                printOpenSSLError();
                EVP_CIPHER_CTX_free(ctx);
                return "";
            }

            { // init ctx
                unsigned char *tag = (unsigned char *)(encryptData.data()+ (encryptData.size() - poly1305_tag_len));
                OSSL_PARAM params[] = {
                    OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_AEAD_IVLEN,
                                            &poly1305_nonce_iv_len),
                    OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, tag, poly1305_tag_len),
                    OSSL_PARAM_END
                };
                const unsigned char *key = (const unsigned char *)secretKey.data();
                const unsigned char *iv = (const unsigned char *)encryptData.data();

                /*
                 * Initialise encrypt operation with the cipher & mode,
                 * nonce/iv length and tag length parameters.
                 */
                if (!EVP_DecryptInit_ex2(ctx, cipher, nullptr, nullptr, params)) {
                    std::cerr << "chaCha20Poly1305_decrypt EVP_DecryptInit_ex2() failed" << std::endl;
                    printOpenSSLError();
                    EVP_CIPHER_free(cipher);
                    EVP_CIPHER_CTX_free(ctx);
                    return "";
                }
                //CCM 模式分两步初始化，不然解密不成功，这种写法来自官方demo。
                /* Initialise key and nonce/iv */
                if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) {
                    std::cerr << "chaCha20Poly1305_decrypt EVP_DecryptInit_ex() failed" << std::endl;
                    printOpenSSLError();
                    EVP_CIPHER_free(cipher);
                    EVP_CIPHER_CTX_free(ctx);
                    return "";
                }
            }


            int ivLength = EVP_CIPHER_get_iv_length(cipher);
            if (ivLength != poly1305_nonce_iv_len) {
                std::cerr << "chaCha20Poly1305_decrypt Invalid IV length : must be 12 bytes" << std::endl;
                EVP_CIPHER_free(cipher);
                EVP_CIPHER_CTX_free(ctx);
                return "";
            }

            if (!aad.empty()) {
                int outlen;
                const unsigned char *aadIn = (const unsigned char *)aad.data();
                if (!EVP_DecryptUpdate(ctx, NULL, &outlen, aadIn, aad.size())) {
                    std::cerr << "chaCha20Poly1305_decrypt EVP_DecryptUpdate() aad failed" << std::endl;
                    EVP_CIPHER_free(cipher);
                    EVP_CIPHER_CTX_free(ctx);
                    return "";
                }
            }


            std::string buffer;
            buffer.resize(std::max((int)encryptData.size() + 8, 512));
            const unsigned char *in = (const unsigned char *)(encryptData.data() + poly1305_nonce_iv_len);
            int inl = encryptData.size() - poly1305_nonce_iv_len - poly1305_tag_len;
            unsigned char *out = (unsigned char *)buffer.data();
            int outl = buffer.size();
            int totalLen = 0;
            if (!EVP_DecryptUpdate(ctx, out, &outl, in, inl)) {
                std::cerr << "chaCha20Poly1305_decrypt EVP_DecryptUpdate() failed" << std::endl;
                printOpenSSLError();
                EVP_CIPHER_free(cipher);
                EVP_CIPHER_CTX_free(ctx);
                return "";
            }
            totalLen += outl;

            int tempLen = buffer.size() - outl;
            if (!EVP_DecryptFinal_ex(ctx, out + outl, &tempLen)) {
                std::cerr << "chaCha20Poly1305_decrypt EVP_DecryptFinal_ex() failed" << std::endl;
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
        ChaCha20Poly1305Encryptor::ChaCha20Poly1305Encryptor(const std::string_view& secret, const std::string_view& format) {
            this->secretKey = getChaCha20Poly1305Key(secret, format);
        }

        std::string ChaCha20Poly1305Encryptor::encrypt(const std::string_view &plainText) const {
            return chaCha20Poly1305_encrypt(secretKey, plainText, "");
        }

        std::string ChaCha20Poly1305Encryptor::encryptToHex(const std::string_view &plainText) const {
            return hex_encode(encrypt(plainText));
        }


        std::string ChaCha20Poly1305Encryptor::encryptToBase64(const std::string_view &plainText) const {
            return base64_encode(encrypt(plainText));
        }

        std::string ChaCha20Poly1305Encryptor::encryptWithAAD(const std::string_view &plainText, const std::string_view &aad) const {
            return chaCha20Poly1305_encrypt(secretKey, plainText, aad);
        }

        std::string ChaCha20Poly1305Encryptor::encryptToHexWithAAD(const std::string_view &plainText, const std::string_view &aad) const {
            return hex_encode(encryptWithAAD(plainText, aad));
        }

        std::string ChaCha20Poly1305Encryptor::encryptToBase64WithAAD(const std::string_view &plainText, const std::string_view &aad) const {
            return base64_encode(encryptWithAAD(plainText, aad));
        }

    }
}

namespace camel {
    namespace crypto {

         ChaCha20Poly1305Decryptor::ChaCha20Poly1305Decryptor(const std::string_view &secret, const std::string_view &format) {
             this->secretKey = getChaCha20Poly1305Key(secret, format);
        }

        std::string ChaCha20Poly1305Decryptor::decrypt(const std::string_view &encryptedData) const {
             return chaCha20Poly1305_decrypt(secretKey, encryptedData, "");
        }

        std::string ChaCha20Poly1305Decryptor::decryptFromHex(const std::string_view &hexEncryptedText) const {
            return decrypt(hex_decode(hexEncryptedText));
        }

        std::string ChaCha20Poly1305Decryptor::decryptFromBase64(const std::string_view &base64EncryptedText) const {
            return decrypt(base64_decode(base64EncryptedText));
        }

        std::string ChaCha20Poly1305Decryptor::decryptWithAAD(const std::string_view &encryptedData, const std::string_view &aad) const {
             return chaCha20Poly1305_decrypt(secretKey, encryptedData, aad);
        }

        std::string ChaCha20Poly1305Decryptor::decryptFromHexWithAAD(const std::string_view &encryptedData, const std::string_view &aad) const {
            return decryptWithAAD(hex_decode(encryptedData), aad);
        }

        std::string ChaCha20Poly1305Decryptor::decryptFromBase64WithAAD(const std::string_view &encryptedData, const std::string_view &aad) const {
            return decryptWithAAD(base64_decode(encryptedData), aad);
        }

    }
}
