//
// Created by baojian on 25-8-14.
//

#include "aes.h"

#include <iostream>
#include <openssl/rand.h>
#include <__ostream/basic_ostream.h>

#include "openssl/core_names.h"

namespace camel {
    namespace crypto {
        AESKeyGenerator::AESKeyGenerator(int keyBitLength) {
            this->mKeyBitLength = keyBitLength;
            this->secretKey.resize(keyBitLength/8);
            unsigned char * buffer = (unsigned char *)secretKey.data();
            if (RAND_priv_bytes(buffer, secretKey.size()) != 1) {
                std::cerr << "AESKeyGenerator::AESKeyGenerator() RAND_priv_bytes() failed" << std::endl;
                printOpenSSLError();
                secretKey = "";
            }
        }

        std::string AESKeyGenerator::getKey() {
            return secretKey;
        }

        std::string AESKeyGenerator::getHexKey() {
            return hex_encode(secretKey);
        }


        std::string AESKeyGenerator::getBase64Key() {
            return base64_encode(secretKey);
        }

    }
}

namespace camel {
    namespace crypto {
        std::string genSivKey(int keyBitLength) {
            std::string secretKey;
            secretKey.resize(keyBitLength/8*2); // ctrl key and mac key.
            unsigned char * out = (unsigned char *)secretKey.data();
            if (RAND_priv_bytes(out, secretKey.size()) != 1) {
                std::cerr << "genSivKey RAND_priv_bytes() failed" << std::endl;
                printOpenSSLError();
                secretKey.resize(0);
            }
            return secretKey;
        }
        std::string genHexSivKey(int keyBitLength) {
            return hex_encode(genSivKey(keyBitLength));
        }
        std::string genBase64ivKey(int keyBitLength) {
            return base64_encode(genSivKey(keyBitLength));
        }

        std::string getAESKey(const std::string_view& secret, const std::string_view& format) {
            if (format == "base64") {
                return base64_decode(secret);
            } else if (format == "hex") {
                return hex_decode(secret);
            }  else if (format == "binary" || format == "raw") {
                return std::string(secret);
            } else {
                return std::string(secret);
            }
        }
    }
}

namespace camel {
    namespace crypto {

        inline bool algorithmHas(const std::string& algorithm, std::string_view target) {
            return algorithm.find(target) != std::string::npos;
        }

        inline std::string aesName(const int keyBitLength, const std::string& mode) {
            std::string name = "AES-";
            if (keyBitLength == 256) {
                name.append("256");
            } else if (keyBitLength== 192) {
                name.append("192");
            } else {
                name.append("128");
            }
            name.append("-");
            name.append(mode);
            return name;
        }

        inline bool isAESKeyBitLenNotValid(const int keyBitLength) {
            return !(keyBitLength == 256
                     || keyBitLength == 192
                     || keyBitLength == 128);
        }

        /**
        * 模式为 ECB	无需 IV（ECB 是独立分组加密，无链式依赖）
        * 模式为 CFB/OFB/CTR/CTS	无需填充（流式 / 特殊分组模式，明文长度无需对齐 AES 分组（16 字节））
        * 其他模式（如 CBC）	需 IV + PKCS#7 填充（默认填充方式）
         * @param plainData
         * @param secretKey
         * @return
         */
        std::string aes_normal_encrypt(const std::string_view &plainData, const std::string& secretKey, const std::string& mode) {
            if (isAESKeyBitLenNotValid(secretKey.size()*8)) {
                std::cerr << "aes_normal_encrypt secretKey size invalid" << std::endl;
                return "";
            }
            EVP_CIPHER_CTX *ctx = nullptr;
            EVP_CIPHER *cipher = nullptr;
            ctx = EVP_CIPHER_CTX_new();
            if (ctx == nullptr) {
                std::cerr << "aes_normal_encrypt EVP_CIPHER_CTX_new() failed" << std::endl;
                printOpenSSLError();
                return "";
            }
            std::string algorithmName = aesName(secretKey.length()*8, mode);

            cipher = EVP_CIPHER_fetch(nullptr, algorithmName.data(), nullptr);
            if (cipher == nullptr) {
                std::cerr << "aes_normal_encrypt EVP_CIPHER_fetch() failed" << std::endl;
                printOpenSSLError();
                EVP_CIPHER_CTX_free(ctx);
                return "";
            }

            bool needPadding = true;
            bool needIV = true;
            if (mode == "ECB") {
                needIV = false;
            }
            if (mode == "CFB"
                || mode == "OFB"
                || mode == "CTR"
                || mode == "CTS") { //CFB、OFB、CTR、CTS 流式加密，无需padding
                needPadding = false;
            }
            std::string combineBuffer; // iv + buffer + tag
            combineBuffer.resize(std::max((int)plainData.size()*2 + 64, 512));

            if (needIV) {
                size_t aes_iv_len = 16;
                unsigned char* iv = (unsigned char* )combineBuffer.data();
                if (RAND_bytes(iv, aes_iv_len) != 1) {
                    std::cerr << "aes_normal_encrypt RAND_bytes() failed" << std::endl;
                    printOpenSSLError();
                    EVP_CIPHER_free(cipher);
                    EVP_CIPHER_CTX_free(ctx);
                    return "";
                }

                OSSL_PARAM params[] = {
                    OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_IVLEN,
                                            &aes_iv_len),
                    OSSL_PARAM_END
                };
                const unsigned char *key = (const unsigned char *)secretKey.data();
                if (!EVP_EncryptInit_ex2(ctx, cipher, key, iv, params)) {
                    std::cerr << "aes_normal_encrypt EVP_EncryptInit_ex2() failed" << std::endl;
                    printOpenSSLError();
                    EVP_CIPHER_free(cipher);
                    EVP_CIPHER_CTX_free(ctx);
                    return "";
                }
            } else {
                OSSL_PARAM params[] = {
                    OSSL_PARAM_END
                };
                const unsigned char *key = (const unsigned char *)secretKey.data();
                if (!EVP_EncryptInit_ex2(ctx, cipher, key, nullptr, params)) {
                    std::cerr << "aes_normal_encrypt EVP_EncryptInit_ex2() failed" << std::endl;
                    printOpenSSLError();
                    EVP_CIPHER_free(cipher);
                    EVP_CIPHER_CTX_free(ctx);
                    return "";
                }
            }
            if (needPadding) {
                if (!EVP_CIPHER_CTX_set_padding(ctx, 1)) {
                    std::cerr << "aes_normal_encrypt EVP_CIPHER_CTX_set_padding failed" << std::endl;
                    printOpenSSLError();
                    EVP_CIPHER_free(cipher);
                    EVP_CIPHER_CTX_free(ctx);
                    return "";
                }
            }
            int ivLength = 0;
            if (needIV) {
                 ivLength = EVP_CIPHER_get_iv_length(cipher);
                if (ivLength != 16) {
                    std::cerr << "aes_normal_encrypt Invalid IV length for AES-CBC: must be 16 bytes" << std::endl;
                    EVP_CIPHER_free(cipher);
                    EVP_CIPHER_CTX_free(ctx);
                    return "";
                }
            }

            const unsigned char *in = (const unsigned char *)(plainData.data());
            int inl = plainData.size();
            unsigned char *out = (unsigned char *)(combineBuffer.data() + ivLength);
            int outl = combineBuffer.size() - ivLength;
            int totalLen = ivLength;
            if (!EVP_EncryptUpdate(ctx, out, &outl, in, inl)) {
                std::cerr << "aes_normal_encryptEVP_EncryptUpdate() failed" << std::endl;
                printOpenSSLError();
                EVP_CIPHER_free(cipher);
                EVP_CIPHER_CTX_free(ctx);
                return "";
            }
            totalLen += outl;
            int tempLen = combineBuffer.size() - ivLength - outl;
            if (!EVP_EncryptFinal_ex(ctx, out + outl, &tempLen)) {
                std::cerr << "aes_normal_encrypt EVP_EncryptFinal_ex() failed" << std::endl;
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

        /**
         *
         * @param encryptData
         * @param secretKey
         * @return
         */
        std::string aes_normal_decrypt(const std::string_view &encryptData, const std::string& secretKey, const std::string& mode) {
            if (isAESKeyBitLenNotValid(secretKey.size()*8)) {
                std::cerr << "aes_normal_decrypt secretKey size invalid" << std::endl;
                return "";
            }
            EVP_CIPHER_CTX *ctx = nullptr;
            EVP_CIPHER *cipher = nullptr;
            ctx = EVP_CIPHER_CTX_new();
            if (ctx == nullptr) {
                std::cerr << "aes_normal_decrypt EVP_CIPHER_CTX_new() failed" << std::endl;
                printOpenSSLError();
                return "";
            }
            std::string algorithmName = aesName(secretKey.length()*8, mode);

            cipher = EVP_CIPHER_fetch(nullptr, algorithmName.data(), nullptr);
            if (cipher == nullptr) {
                std::cerr << "aes_normal_decrypt EVP_CIPHER_fetch() failed" << std::endl;
                printOpenSSLError();
                EVP_CIPHER_CTX_free(ctx);
                return "";
            }

            bool needPadding = true;
            bool needIV = true;
            if (mode == "ECB") {
                needIV = false;
            }
            if (mode == "CFB"
                || mode == "OFB"
                || mode == "CTR"
                || mode == "CTS") { //CFB、OFB、CTR、CTS 流式加密，无需padding
                needPadding = false;
            }

            if (needIV) {
                if (encryptData.size() <= 16) {
                    std::cerr << "aes_normal_decrypt illegal, encryptData too short " << std::endl;
                    return "";
                }
                OSSL_PARAM params[] = {
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
            } else {
                OSSL_PARAM params[] = {
                    OSSL_PARAM_END
                };
                const unsigned char *key = (const unsigned char *)secretKey.data();
                if (!EVP_DecryptInit_ex2(ctx, cipher, key, nullptr, params)) {
                    std::cerr << "aaes_normal_decrypt EVP_DecryptInit_ex2() failed" << std::endl;
                    printOpenSSLError();
                    EVP_CIPHER_free(cipher);
                    EVP_CIPHER_CTX_free(ctx);
                    return "";
                }
            }
            if (needPadding) {
                if (!EVP_CIPHER_CTX_set_padding(ctx, 1)) {
                    std::cerr << "aes_normal_decrypt EVP_CIPHER_CTX_set_padding failed" << std::endl;
                    printOpenSSLError();
                    EVP_CIPHER_free(cipher);
                    EVP_CIPHER_CTX_free(ctx);
                    return "";
                }
            }
            int ivLength = 0;
            if (needIV) {
                 ivLength = EVP_CIPHER_get_iv_length(cipher);
                if (ivLength != 16) {
                    std::cerr << "aes_normal_decrypt Invalid IV length for AES-CBC: must be 16 bytes" << std::endl;
                    EVP_CIPHER_free(cipher);
                    EVP_CIPHER_CTX_free(ctx);
                    return "";
                }
            }

            std::string buffer;
            buffer.resize(std::max((int)encryptData.size() + 8, 512));
            const unsigned char *in = (const unsigned char *)(encryptData.data() + ivLength);
            int inl = encryptData.size() - ivLength;
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

         std::string aes_gcm_ccm_encrypt(const std::string_view &plainData,
            const std::string& secretKey,
            const std::string& mode,
            const std::string_view &aad) {
            if (isAESKeyBitLenNotValid(secretKey.size()*8)) {
                std::cerr << "aes_gcm_ccm_encrypt secretKey size invalid " << std::endl;
                return "";
            }

            int gcm_iv_len = 12; // ccm模式的once
            int gcm_tag_len = 16; // ccm的tag

            EVP_CIPHER_CTX *ctx = nullptr;
            EVP_CIPHER *cipher = nullptr;
            ctx = EVP_CIPHER_CTX_new();
            if (ctx == nullptr) {
                std::cerr << "aes_gcm_ccm_decrypt EVP_CIPHER_CTX_new() failed" << std::endl;
                printOpenSSLError();
                return "";
            }
            std::string algorithmName = aesName(secretKey.length()*8, mode);

            cipher = EVP_CIPHER_fetch(nullptr, algorithmName.data(), nullptr);
            if (cipher == nullptr) {
                std::cerr << "aes_gcm_ccm_decrypt EVP_CIPHER_fetch() failed" << std::endl;
                printOpenSSLError();
                EVP_CIPHER_CTX_free(ctx);
                return "";
            }
            std::string combineBuffer; // iv + buffer + tag
            combineBuffer.resize(std::max((int)plainData.size()*2 + 64, 512));

            { // init ctx
                unsigned char* iv = (unsigned char* )combineBuffer.data();
                if (RAND_bytes(iv, gcm_iv_len) != 1) {
                    std::cerr << "aes_siv_encrypt RAND_bytes() failed" << std::endl;
                    printOpenSSLError();
                    EVP_CIPHER_free(cipher);
                    EVP_CIPHER_CTX_free(ctx);
                    return "";
                }

                OSSL_PARAM params[] = {
                    OSSL_PARAM_construct_int(OSSL_CIPHER_PARAM_AEAD_IVLEN,
                                            &gcm_iv_len),
                    OSSL_PARAM_construct_int(OSSL_CIPHER_PARAM_AEAD_TAGLEN,
                                           &gcm_tag_len),
                    OSSL_PARAM_END
                };
                const unsigned char *key = (const unsigned char *)secretKey.data();
                /*
                 * Initialise encrypt operation with the cipher & mode,
                 * nonce/iv length and tag length parameters.
                 */
                if (!EVP_EncryptInit_ex2(ctx, cipher, nullptr, nullptr, params)) {
                    std::cerr << "aes_gcm_ccm_decrypt EVP_EncryptInit_ex2() failed" << std::endl;
                    printOpenSSLError();
                    EVP_CIPHER_free(cipher);
                    EVP_CIPHER_CTX_free(ctx);
                    return "";
                }
                // 分两步初始化，参考解密
                /* Initialise key and nonce/iv */
                if (!EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) {
                    std::cerr << "aes_gcm_ccm_decrypt EVP_EncryptInit_ex() failed" << std::endl;
                    printOpenSSLError();
                    EVP_CIPHER_free(cipher);
                    EVP_CIPHER_CTX_free(ctx);
                    return "";
                }
            }


            int ivLength = EVP_CIPHER_get_iv_length(cipher);
            if (ivLength != gcm_iv_len) {
                std::cerr << "aes_gcm_ccm_decrypt Invalid IV length for AES-GCM: must be 12 bytes" << std::endl;
                EVP_CIPHER_free(cipher);
                EVP_CIPHER_CTX_free(ctx);
                return "";
            }

            if (!aad.empty()) {
                int outlen;
                const unsigned char *aadIn = (const unsigned char *)aad.data();
                if (!EVP_EncryptUpdate(ctx, NULL, &outlen, aadIn, aad.size())) {
                    std::cerr << "aes_gcm_ccm_decrypt EVP_EncryptUpdate() aad failed" << std::endl;
                    EVP_CIPHER_free(cipher);
                    EVP_CIPHER_CTX_free(ctx);
                    return "";
                }
            }

            const unsigned char *in = (const unsigned char *)(plainData.data());
            int inl = plainData.size();
            unsigned char *out = (unsigned char *) combineBuffer.data() + gcm_iv_len;
            int outl = combineBuffer.size() - gcm_iv_len - gcm_tag_len;
            int totalLen = gcm_iv_len + gcm_tag_len;
            if (!EVP_EncryptUpdate(ctx, out, &outl, in, inl)) {
                std::cerr << "aes_gcm_ccm_decrypt EVP_EncryptUpdate() failed" << std::endl;
                printOpenSSLError();
                EVP_CIPHER_free(cipher);
                EVP_CIPHER_CTX_free(ctx);
                return "";
            }
            totalLen += outl;

            int tempLen = combineBuffer.size() - gcm_iv_len - gcm_tag_len - outl;
            if (!EVP_EncryptFinal_ex(ctx, out + outl, &tempLen)) {
                std::cerr << "aes_gcm_ccm_decrypt EVP_EncryptFinal_ex() failed" << std::endl;
                printOpenSSLError();
                EVP_CIPHER_free(cipher);
                EVP_CIPHER_CTX_free(ctx);
                return "";
            }
            totalLen += tempLen;

            unsigned char* tag = (unsigned char*)(combineBuffer.data() + totalLen - gcm_tag_len);
            OSSL_PARAM params[] = {
                OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, tag, gcm_tag_len),
                OSSL_PARAM_END
            };
            if (!EVP_CIPHER_CTX_get_params(ctx, params)) {
                std::cerr << "aes_siv_encrypt EVP_CIPHER_CTX_get_params() failed" << std::endl;
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

        std::string aes_gcm_ccm_decrypt(const std::string_view &encryptData,
            const std::string& secretKey,
            const std::string& mode,
            const std::string_view &aad) {

            if (isAESKeyBitLenNotValid(secretKey.size()*8)) {
                std::cerr << "aes_gcm_ccm_decrypt secretKey size invalid" << std::endl;
                return "";
            }
            size_t gcm_iv_len = 12; // ccm模式的once
            size_t gcm_tag_len = 16; // ccm的tag
            if (encryptData.size() <= (gcm_iv_len + gcm_tag_len)) {
                std::cerr << "aes_gcm_ccm_decrypt illegal, encryptData too short " << std::endl;
                return "";
            }
            EVP_CIPHER_CTX *ctx = nullptr;
            EVP_CIPHER *cipher = nullptr;
            ctx = EVP_CIPHER_CTX_new();
            if (ctx == nullptr) {
                std::cerr << "aes_gcm_ccm_decrypt EVP_CIPHER_CTX_new() failed" << std::endl;
                printOpenSSLError();
                return "";
            }
            std::string algorithmName = aesName(secretKey.length()*8, mode);

            cipher = EVP_CIPHER_fetch(nullptr, algorithmName.data(), nullptr);
            if (cipher == nullptr) {
                std::cerr << "aes_gcm_ccm_decrypt EVP_CIPHER_fetch() failed" << std::endl;
                printOpenSSLError();
                EVP_CIPHER_CTX_free(ctx);
                return "";
            }

            { // init ctx
                unsigned char *tag = (unsigned char *)(encryptData.data()+ (encryptData.size() - gcm_tag_len));
                OSSL_PARAM params[] = {
                    OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_AEAD_IVLEN,
                                            &gcm_iv_len),
                    OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, tag, gcm_tag_len),
                    OSSL_PARAM_END
                };
                const unsigned char *key = (const unsigned char *)secretKey.data();
                const unsigned char *iv = (const unsigned char *)encryptData.data();

                /*
                 * Initialise encrypt operation with the cipher & mode,
                 * nonce/iv length and tag length parameters.
                 */
                if (!EVP_DecryptInit_ex2(ctx, cipher, nullptr, nullptr, params)) {
                    std::cerr << "aes_gcm_ccm_decrypt EVP_DecryptInit_ex2() failed" << std::endl;
                    printOpenSSLError();
                    EVP_CIPHER_free(cipher);
                    EVP_CIPHER_CTX_free(ctx);
                    return "";
                }
                //CCM 模式分两步初始化，不然解密不成功，这种写法来自官方demo。
                /* Initialise key and nonce/iv */
                if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) {
                    std::cerr << "aes_gcm_ccm_decrypt EVP_DecryptInit_ex() failed" << std::endl;
                    printOpenSSLError();
                    EVP_CIPHER_free(cipher);
                    EVP_CIPHER_CTX_free(ctx);
                    return "";
                }
            }


            int ivLength = EVP_CIPHER_get_iv_length(cipher);
            if (ivLength != gcm_iv_len) {
                std::cerr << "aes_gcm_ccm_decrypt Invalid IV length for AES-GCM: must be 12 bytes" << std::endl;
                EVP_CIPHER_free(cipher);
                EVP_CIPHER_CTX_free(ctx);
                return "";
            }

            if (!aad.empty()) {
                int outlen;
                const unsigned char *aadIn = (const unsigned char *)aad.data();
                if (!EVP_DecryptUpdate(ctx, NULL, &outlen, aadIn, aad.size())) {
                    std::cerr << "aes_gcm_ccm_decrypt EVP_DecryptUpdate() aad failed" << std::endl;
                    EVP_CIPHER_free(cipher);
                    EVP_CIPHER_CTX_free(ctx);
                    return "";
                }
            }


            std::string buffer;
            buffer.resize(std::max((int)encryptData.size() + 8, 512));
            const unsigned char *in = (const unsigned char *)(encryptData.data() + gcm_iv_len);
            int inl = encryptData.size() - gcm_iv_len - gcm_tag_len;
            unsigned char *out = (unsigned char *)buffer.data();
            int outl = buffer.size();
            int totalLen = 0;
            if (!EVP_DecryptUpdate(ctx, out, &outl, in, inl)) {
                std::cerr << "aes_gcm_ccm_decrypt EVP_DecryptUpdate() failed" << std::endl;
                printOpenSSLError();
                EVP_CIPHER_free(cipher);
                EVP_CIPHER_CTX_free(ctx);
                return "";
            }
            totalLen += outl;

            int tempLen = buffer.size() - outl;
            if (!EVP_DecryptFinal_ex(ctx, out + outl, &tempLen)) {
                std::cerr << "aes_gcm_ccm_decrypt EVP_DecryptFinal_ex() failed" << std::endl;
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

        std::string aes_siv_encrypt(const std::string_view &plainData, const std::string& secretKey, const std::string_view& aad) {
            if (isAESKeyBitLenNotValid(secretKey.size()*8/2)) {
                std::cerr << "aes_siv_encrypt secretKey size invalid" << std::endl;
                return "";
            }
            EVP_CIPHER_CTX *ctx = nullptr;
            EVP_CIPHER *cipher = nullptr;
            ctx = EVP_CIPHER_CTX_new();
            if (ctx == nullptr) {
                std::cerr << "aes_siv_encrypt EVP_CIPHER_CTX_new() failed" << std::endl;
                printOpenSSLError();
                return "";
            }

            // siv包含2倍长度秘钥, 位ctrlkey和 mackkey组层
            std::string algorithmName = aesName(secretKey.length()*8/2, "SIV");

            cipher = EVP_CIPHER_fetch(nullptr, algorithmName.data(), nullptr);
            if (cipher == nullptr) {
                std::cerr << "aes_siv_encrypt EVP_CIPHER_fetch() failed" << std::endl;
                printOpenSSLError();
                EVP_CIPHER_CTX_free(ctx);
                return "";
            }
            size_t siv_iv_length = 16; // iv(tag) + buffer
            std::string combineBuffer; // iv(tag) + buffer
            combineBuffer.resize(std::max((int)plainData.size()*2 + 64, 512));

            {
                //for siv mode, iv will be auto generate by mac key
                unsigned char* iv =  nullptr;
                const unsigned char *key = (const unsigned char *)secretKey.data();
                OSSL_PARAM params[] = {
                    OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_AEAD_IVLEN, &siv_iv_length),
                    OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_AEAD_TAGLEN,
                                           &siv_iv_length),
                    OSSL_PARAM_END
                };
                /*
                 * Initialise encrypt operation with the cipher & mode,
                 * nonce/iv length and tag length parameters.
                 */
                if (!EVP_EncryptInit_ex2(ctx, cipher, nullptr, nullptr, params)) {
                    std::cerr << "aes_siv_encrypt EVP_EncryptInit_ex2() failed" << std::endl;
                    printOpenSSLError();
                    EVP_CIPHER_free(cipher);
                    EVP_CIPHER_CTX_free(ctx);
                    return "";
                }

                /* Initialise key and nonce/iv (AES-SIV) use mackey to gen iv */
                if (!EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) {
                    std::cerr << "aes_siv_encrypt EVP_EncryptInit_ex() failed" << std::endl;
                    printOpenSSLError();
                    EVP_CIPHER_free(cipher);
                    EVP_CIPHER_CTX_free(ctx);
                    return "";
                }
            }


            if (!aad.empty()) {
                int outlen;
                const unsigned char *aadIn = (const unsigned char *)aad.data();
                if (!EVP_EncryptUpdate(ctx, NULL, &outlen, aadIn, aad.size())) {
                    std::cerr << "aes_siv_encrypt EVP_EncryptUpdate() aad failed" << std::endl;
                    EVP_CIPHER_free(cipher);
                    EVP_CIPHER_CTX_free(ctx);
                    return "";
                }
            }

            const unsigned char *in = (const unsigned char *)(plainData.data());
            int plainTextSize = plainData.size();
            unsigned char *out = (unsigned char *)combineBuffer.data() + siv_iv_length;
            int outl = combineBuffer.size() - siv_iv_length;
            int totalLen = 0;
            if (!EVP_EncryptUpdate(ctx, out, &outl, in, plainTextSize)) {
                std::cerr << "aes_siv_encrypt EVP_DecryptUpdate() failed" << std::endl;
                printOpenSSLError();
                EVP_CIPHER_free(cipher);
                EVP_CIPHER_CTX_free(ctx);
                return "";
            }
            totalLen += outl;
            int tempLen = combineBuffer.size() - totalLen;
            if (!EVP_EncryptFinal_ex(ctx, out + outl, &tempLen)) {
                std::cerr << "aes_siv_encrypt EVP_DecryptFinal_ex() failed" << std::endl;
                printOpenSSLError();
                EVP_CIPHER_free(cipher);
                EVP_CIPHER_CTX_free(ctx);
                return "";
            }
            totalLen += tempLen;

            unsigned char* tag = (unsigned char*)combineBuffer.data();
            OSSL_PARAM params[] = {
                OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, tag, siv_iv_length),
                OSSL_PARAM_END
            };
            if (!EVP_CIPHER_CTX_get_params(ctx, params)) {
                std::cerr << "aes_siv_encrypt EVP_CIPHER_CTX_get_params() failed" << std::endl;
                printOpenSSLError();
                EVP_CIPHER_free(cipher);
                EVP_CIPHER_CTX_free(ctx);
                return "";
            }
            totalLen += siv_iv_length;

            combineBuffer.resize(totalLen);
            EVP_CIPHER_free(cipher);
            EVP_CIPHER_CTX_free(ctx);
            return combineBuffer;
        }



         std::string aes_siv_decrypt(const std::string_view &encryptData, const std::string& secretKey, const std::string_view& aad) {
            if (isAESKeyBitLenNotValid(secretKey.size()*8/2)) {
                std::cerr << "aes_siv_decrypt secretKey size invalid" << std::endl;
                return "";
            }
            const int siv_iv_length = 16;
            if (encryptData.size() <= siv_iv_length) {
                std::cerr << "aes_siv_decrypt illegal encrypt data, two short" << std::endl;
                return "";
            }
            EVP_CIPHER_CTX *ctx = nullptr;
            EVP_CIPHER *cipher = nullptr;
            ctx = EVP_CIPHER_CTX_new();
            if (ctx == nullptr) {
                std::cerr << "aes_siv_decrypt EVP_CIPHER_CTX_new() failed" << std::endl;
                printOpenSSLError();
                return "";
            }


            //std::string macKey(secretKey.data() + secretKey.size()/2, secretKey.size()/2);
            // siv包含2倍长度秘钥
            std::string algorithmName = aesName(secretKey.length()*8/2, "SIV");

            cipher = EVP_CIPHER_fetch(nullptr, algorithmName.data(), nullptr);
            if (cipher == nullptr) {
                std::cerr << "aes_siv_decrypt EVP_CIPHER_fetch() failed" << std::endl;
                printOpenSSLError();
                EVP_CIPHER_CTX_free(ctx);
                return "";
            }

            { // init siv ctx
                const unsigned char *key = (const unsigned char *)secretKey.data();
                //AES-SIV 模式， iv和tag是一个字段， 必须设置iv
                const unsigned char *iv = (const unsigned char *)encryptData.data();
                unsigned char *tag = (unsigned char *)(encryptData.data());
                OSSL_PARAM params[] = {
                    OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, tag, siv_iv_length),
                    OSSL_PARAM_END
                };
                /*
                 * Initialise encrypt operation with the cipher & mode,
                 * nonce/iv length and tag length parameters.
                 */
                if (!EVP_DecryptInit_ex2(ctx, cipher, nullptr, nullptr, params)) {
                    std::cerr << "aes_siv_decrypt EVP_DecryptInit_ex2() failed" << std::endl;
                    printOpenSSLError();
                    EVP_CIPHER_free(cipher);
                    EVP_CIPHER_CTX_free(ctx);
                    return "";
                }
                //CCM 模式分两步初始化，不然解密不成功，这种写法来自官方demo。
                /* Initialise key and nonce/iv */
                if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) {
                    std::cerr << "aes_siv_decrypt EVP_DecryptInit_ex() failed" << std::endl;
                    printOpenSSLError();
                    EVP_CIPHER_free(cipher);
                    EVP_CIPHER_CTX_free(ctx);
                    return "";
                }
            }

            if (!aad.empty()) {
                int outlen;
                const unsigned char *aadIn = (const unsigned char *)aad.data();
                if (!EVP_DecryptUpdate(ctx, NULL, &outlen, aadIn, aad.size())) {
                    std::cerr << "aes_siv_decrypt EVP_DecryptUpdate() aad failed" << std::endl;
                    EVP_CIPHER_free(cipher);
                    EVP_CIPHER_CTX_free(ctx);
                    return "";
                }
            }

            std::string buffer;
            buffer.resize(std::max((int)encryptData.size() + 8, 512));
            const unsigned char *in = (const unsigned char *)(encryptData.data() + siv_iv_length);
            int inl = encryptData.size() - siv_iv_length;
            unsigned char *out = (unsigned char *)buffer.data();
            int outl = buffer.size();
            int totalLen = 0;
            if (!EVP_DecryptUpdate(ctx, out, &outl, in, inl)) {
                std::cerr << "aes_siv_decrypt EVP_DecryptUpdate() failed" << std::endl;
                printOpenSSLError();
                EVP_CIPHER_free(cipher);
                EVP_CIPHER_CTX_free(ctx);
                return "";
            }
            totalLen += outl;
            int tempLen = buffer.size() - outl;
            if (!EVP_DecryptFinal_ex(ctx, out + outl, &tempLen)) {
                std::cerr << "aes_siv_decrypt EVP_DecryptFinal_ex() failed" << std::endl;
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
        AESEncryptor::AESEncryptor(const std::string& algorithm, const std::string_view& secret, const std::string& format) {
            this->algorithm = algorithm;
            this->secretKey = getAESKey(secret, format);
        }

        std::string AESEncryptor::encrypt(const std::string_view &plainText) const {
            if (algorithmHas(algorithm, "CBC")) {
                return aes_normal_encrypt(plainText, secretKey, "CBC");
            }
            if (algorithmHas(algorithm, "CFB")) {
                return aes_normal_encrypt(plainText, secretKey, "CFB");
            }
            if (algorithmHas(algorithm, "CTR")) {
                return aes_normal_encrypt(plainText,  secretKey, "CTR");
            }
            if (algorithmHas(algorithm, "CTS")) {
                std::cerr << "AESDecryptor::decrypt CTS not support, please use AES-CBC" << std::endl;
                return "";
            }

            if (algorithmHas(algorithm, "ECB")) {
                return aes_normal_encrypt(plainText, secretKey, "ECB");
            }

            if (algorithmHas(algorithm, "OFB")) {
                return aes_normal_encrypt(plainText, secretKey, "OFB");
            }
            if (algorithmHas(algorithm, "GCM-SIV")) {
                return aes_gcm_ccm_encrypt(plainText, secretKey, "GCM-SIV", "");
            }

            if (algorithmHas(algorithm, "GCM")) {
                return aes_gcm_ccm_encrypt(plainText,  secretKey, "GCM", "");
            }
            if (algorithmHas(algorithm, "CCM")) {
                return aes_gcm_ccm_encrypt(plainText, secretKey, "CCM", "");
            }

            if (algorithmHas(algorithm, "AES-SIV") || algorithmHas(algorithm, "AES/SIV")) {
                return aes_siv_encrypt(plainText, secretKey, "");
            }

            std::cerr << "AESEncryptor::encrypt() not supported algorithm " << algorithm << std::endl;
            return "";
        }

        std::string AESEncryptor::encryptToHex(const std::string_view &plainText) const {
            return hex_encode(encrypt(plainText));
        }


        std::string AESEncryptor::encryptToBase64(const std::string_view &plainText) const {
            return base64_encode(encrypt(plainText));
        }

        std::string AESEncryptor::encryptWithAAD(const std::string_view &plainText, const std::string_view &aad) const {
            if (algorithmHas(algorithm, "GCM-SIV")) {
                return aes_gcm_ccm_encrypt(plainText, secretKey, "GCM-SIV", aad);
            }

            if (algorithmHas(algorithm, "GCM")) {
                return aes_gcm_ccm_encrypt(plainText, secretKey, "GCM", aad);
            }
            if (algorithmHas(algorithm, "CCM")) {
                return aes_gcm_ccm_encrypt(plainText, secretKey, "CCM", aad);
            }
            if (algorithmHas(algorithm, "AES-SIV") || algorithmHas(algorithm, "AES/SIV")) {
                return aes_siv_encrypt(plainText, secretKey, aad);
            }
            std::cerr << "AESEncryptor::encryptWithAAD() not supported algorithm " << algorithm << std::endl;
            return "";
        }

        std::string AESEncryptor::encryptToHexWithAAD(const std::string_view &plainText, const std::string_view &aad) const {
            return hex_encode(encryptWithAAD(plainText, aad));
        }

        std::string AESEncryptor::encryptToBase64WithAAD(const std::string_view &plainText, const std::string_view &aad) const {
            return base64_encode(encryptWithAAD(plainText, aad));
        }

    }
}

namespace camel {
    namespace crypto {
        AESDecryptor::AESDecryptor(const std::string &algorithm, const std::string_view &secret, const std::string &format) {
            this->algorithm = algorithm;
            this->secretKey = getAESKey(secret, format);
        }

        /**
        * 模式	支持情况（主流 Android 版本）	备注
        * CBC	全版本支持	需搭配填充（如 PKCS5Padding）
        * ECB	支持但不推荐	无安全性（块独立加密），官方不建议使用
        * GCM	API 10+ 支持	AEAD 模式（同时提供加密和认证），推荐使用
        * GCM-SIV	API 28+ 支持	GCM 的变体，抗重放攻击更强
        * CTR	支持	流模式，无需填充，适合任意长度数据
        * CFB/OFB	部分版本支持	流模式，兼容性不如 CTR/GCM
        * CTS	几乎不支持	未纳入主流加密提供商实现，极少被支持. CTS暂时不支持
        *   CBC ECB CTR CFB OFB
         *  https://developer.android.com/reference/javax/crypto/Cipher
         * @param encryptedData
         * @return
         */
        std::string AESDecryptor::decrypt(const std::string_view &encryptedData) const {
            if (algorithmHas(algorithm, "CBC")) {
                return aes_normal_decrypt(encryptedData, secretKey, "CBC");
            }
            if (algorithmHas(algorithm, "CFB")) {
                return aes_normal_decrypt(encryptedData, secretKey, "CFB");
            }
            if (algorithmHas(algorithm, "CTR")) {
                return aes_normal_decrypt(encryptedData, secretKey, "CTR");
            }
            if (algorithmHas(algorithm, "CTS")) {
                std::cerr << "AESDecryptor::decrypt CTS not support, please use AES-CBC" << std::endl;
                return "";
            }

            if (algorithmHas(algorithm, "ECB")) {
                return aes_normal_decrypt(encryptedData, secretKey, "ECB");
            }

            if (algorithmHas(algorithm, "OFB")) {
                return aes_normal_decrypt(encryptedData, secretKey, "OFB");
            }

            if (algorithmHas(algorithm, "GCM-SIV")) {
                return aes_gcm_ccm_decrypt(encryptedData, secretKey, "GCM-SIV", "");
            }

            if (algorithmHas(algorithm, "GCM")) {
                return aes_gcm_ccm_decrypt(encryptedData, secretKey, "GCM", "");
            }
            if (algorithmHas(algorithm, "CCM")) {
                return aes_gcm_ccm_decrypt(encryptedData, secretKey, "CCM", "");
            }

            if (algorithmHas(algorithm, "AES-SIV") || algorithmHas(algorithm, "AES/SIV")) {
                return aes_siv_decrypt(encryptedData, secretKey, "");
            }

            std::cerr << "AESDecryptor::decrypt() not supported algorithm " << algorithm << std::endl;
            return "";
        }

        std::string AESDecryptor::decryptFromHex(const std::string_view &hexEncryptedText) const {
            return decrypt(hex_decode(hexEncryptedText));
        }

        std::string AESDecryptor::decryptFromBase64(const std::string_view &base64EncryptedText) const {
            return decrypt(base64_decode(base64EncryptedText));
        }

        std::string AESDecryptor::decryptWithAAD(const std::string_view &encryptedData, const std::string_view &aad) const {
            if (algorithmHas(algorithm, "GCM-SIV")) {
                return aes_gcm_ccm_decrypt(encryptedData, secretKey, "GCM-SIV", aad);
            }

            if (algorithmHas(algorithm, "GCM")) {
                return aes_gcm_ccm_decrypt(encryptedData, secretKey, "GCM", aad);
            }
            if (algorithmHas(algorithm, "CCM")) {
                return aes_gcm_ccm_decrypt(encryptedData, secretKey, "CCM", aad);
            }
            if (algorithmHas(algorithm, "AES-SIV") || algorithmHas(algorithm, "AES/SIV")) {
                return aes_siv_decrypt(encryptedData, secretKey, aad);
            }
            std::cerr << "AESDecryptor::decryptWithAAD() not supported algorithm " << algorithm << std::endl;
            return "";
        }

        std::string AESDecryptor::decryptFromHexWithAAD(const std::string_view &encryptedData, const std::string_view &aad) const {
            return decryptWithAAD(hex_decode(encryptedData), aad);
        }

        std::string AESDecryptor::decryptFromBase64WithAAD(const std::string_view &encryptedData, const std::string_view &aad) const {
            return decryptWithAAD(base64_decode(encryptedData), aad);
        }

    }
}

namespace camel {
    namespace crypto {
        inline std::string aesEncrypt(const std::string& algorithm,
            const std::string_view& aesKey,
            const std::string_view& data) {
            if (isAESKeyBitLenNotValid(aesKey.size()*8)) {
                std::cerr << "aes secretKey size invalid" << algorithm << std::endl;
                return "";
            }
            AESEncryptor aesEncryptor(algorithm, aesKey, "raw");
            return aesEncryptor.encrypt(data);
        }

        inline std::string aesEncryptToHex(const std::string& algorithm,
          const std::string_view& aesKey,
          const std::string_view& data) {
            if (isAESKeyBitLenNotValid(aesKey.size()*8)) {
                std::cerr << "aes secretKey size invalid" << algorithm << std::endl;
                return "";
            }
            AESEncryptor aesEncryptor(algorithm, aesKey, "raw");
            return aesEncryptor.encryptToHex(data);
        }

        inline std::string aesEncryptToBase64(const std::string& algorithm,
             const std::string_view& aesKey,
             const std::string_view& data) {
            if (isAESKeyBitLenNotValid(aesKey.size()*8)) {
                std::cerr << "aes secretKey size invalid" << algorithm << std::endl;
                return "";
            }
            AESEncryptor aesEncryptor(algorithm, aesKey, "raw");
            return aesEncryptor.encryptToBase64(data);
        }

        inline std::string aesDecrypt(const std::string& algorithm,
        const std::string_view& aesKey,
        const std::string_view& data) {
            if (isAESKeyBitLenNotValid(aesKey.size()*8)) {
                std::cerr << "aes secretKey size invalid" << algorithm << std::endl;
                return "";
            }
            AESDecryptor aesDecryptor(algorithm, aesKey, "raw");
            return aesDecryptor.decrypt(data);
        }

        inline std::string aesDecryptFromHex(const std::string& algorithm,
          const std::string_view& aesKey,
          const std::string_view& data) {
            if (isAESKeyBitLenNotValid(aesKey.size()*8)) {
                std::cerr << "aes secretKey size invalid" << algorithm << std::endl;
                return "";
            }
            AESDecryptor aesDecryptor(algorithm, aesKey, "raw");
            return aesDecryptor.decryptFromHex(data);
        }

        inline std::string aesDecryptFromBase64(const std::string& algorithm,
             const std::string_view& aesKey,
             const std::string_view& data) {
            if (isAESKeyBitLenNotValid(aesKey.size()*8)) {
                std::cerr << "aes secretKey size invalid" << algorithm << std::endl;
                return "";
            }
            AESDecryptor aesDecryptor(algorithm, aesKey, "raw");
            return aesDecryptor.decryptFromBase64(data);
        }

        inline std::string aesEncryptWithAAD(const std::string& algorithm,
            const std::string_view& aesKey,
            const std::string_view& data,
             const std::string_view &aad) {
            if (isAESKeyBitLenNotValid(aesKey.size()*8)) {
                std::cerr << "aes secretKey size invalid" << algorithm << std::endl;
                return "";
            }
            AESEncryptor aesEncryptor(algorithm, aesKey, "raw");
            return aesEncryptor.encryptWithAAD(data, aad);
        }

        inline std::string aesEncryptToHexWithAAD(const std::string& algorithm,
          const std::string_view& aesKey,
          const std::string_view& data,
             const std::string_view &aad) {
            if (isAESKeyBitLenNotValid(aesKey.size()*8)) {
                std::cerr << "aes secretKey size invalid" << algorithm << std::endl;
                return "";
            }
            AESEncryptor aesEncryptor(algorithm, aesKey, "raw");
            return aesEncryptor.encryptToHexWithAAD(data, aad);
        }

        inline std::string aesEncryptToBase64WithAAD(const std::string& algorithm,
             const std::string_view& aesKey,
             const std::string_view& data,
             const std::string_view &aad) {
            if (isAESKeyBitLenNotValid(aesKey.size()*8)) {
                std::cerr << "aes secretKey size invalid" << algorithm << std::endl;
                return "";
            }
            AESEncryptor aesEncryptor(algorithm, aesKey, "raw");
            return aesEncryptor.encryptToBase64WithAAD(data, aad);
        }

        inline std::string aesDecryptWithAAD(const std::string& algorithm,
        const std::string_view& aesKey,
        const std::string_view& data,
             const std::string_view &aad) {
            if (isAESKeyBitLenNotValid(aesKey.size()*8)) {
                std::cerr << "aes secretKey size invalid" << algorithm << std::endl;
                return "";
            }
            AESDecryptor aesDecryptor(algorithm, aesKey, "raw");
            return aesDecryptor.decryptWithAAD(data, aad);
        }

        inline std::string aesDecryptFromHexWithAAD(const std::string& algorithm,
          const std::string_view& aesKey,
          const std::string_view& data,
             const std::string_view &aad) {
            if (isAESKeyBitLenNotValid(aesKey.size()*8)) {
                std::cerr << "aes secretKey size invalid" << algorithm << std::endl;
                return "";
            }
            AESDecryptor aesDecryptor(algorithm, aesKey, "raw");
            return aesDecryptor.decryptFromHexWithAAD(data, aad);
        }

        inline std::string aesDecryptFromBase64WithAAD(const std::string& algorithm,
             const std::string_view& aesKey,
             const std::string_view& data,
             const std::string_view &aad) {
            if (isAESKeyBitLenNotValid(aesKey.size()*8)) {
                std::cerr << "aes secretKey size invalid" << algorithm << std::endl;
                return "";
            }
            AESDecryptor aesDecryptor(algorithm, aesKey, "raw");
            return aesDecryptor.decryptFromBase64WithAAD(data, aad);
        }


       namespace AESCBCUtils {
            std::string encrypt(const std::string_view& aesKey, const std::string_view& data) {
                return aesEncrypt("AES-CBC", aesKey, data);
            }
            std::string encryptToHex(const std::string_view& aesKey, const std::string_view& data) {
                return aesEncryptToHex("AES-CBC", aesKey, data);
            }
            std::string encryptToBase64(const std::string_view& aesKey, const std::string_view& data) {
                return aesEncryptToBase64("AES-CBC", aesKey, data);
            }
            std::string decrypt(const std::string_view& aesKey, const std::string_view& data) {
                return aesDecrypt("AES-CBC", aesKey, data);
            }
            std::string decryptFromHex(const std::string_view& aesKey, const std::string_view& data) {
                return aesDecryptFromHex("AES-CBC", aesKey, data);
            }
            std::string decryptFromBase64(const std::string_view& aesKey, const std::string_view& data) {
                return aesDecryptFromBase64("AES-CBC", aesKey, data);
            }
        }

        namespace AESGCMUtils {
            std::string encrypt(const std::string_view& aesKey, const std::string_view& data) {
                return aesEncrypt("AES-GCM", aesKey, data);
            }
            std::string encryptToHex(const std::string_view& aesKey, const std::string_view& data) {
                return aesEncryptToHex("AES-GCM", aesKey, data);
            }
            std::string encryptToBase64(const std::string_view& aesKey, const std::string_view& data) {
                return aesEncryptToBase64("AES-GCM", aesKey, data);
            }
            std::string decrypt(const std::string_view& aesKey, const std::string_view& data) {
                return aesDecrypt("AES-GCM", aesKey, data);
            }
            std::string decryptFromHex(const std::string_view& aesKey, const std::string_view& data) {
                return aesDecryptFromHex("AES-GCM", aesKey, data);
            }
            std::string decryptFromBase64(const std::string_view& aesKey, const std::string_view& data) {
                return aesDecryptFromBase64("AES-GCM", aesKey, data);
            }

            std::string encryptWithAAD(const std::string_view& aesKey, const std::string_view& data, const std::string_view &aad) {
                return aesEncryptWithAAD("AES-GCM", aesKey, data, aad);
            }
            std::string encryptToHexWithAAD(const std::string_view& aesKey, const std::string_view& data, const std::string_view &aad) {
                return aesEncryptToHexWithAAD("AES-GCM", aesKey, data, aad);
            }
            std::string encryptToBase64WithAAD(const std::string_view& aesKey, const std::string_view& data, const std::string_view &aad) {
                return aesEncryptToBase64WithAAD("AES-GCM", aesKey, data, aad);
            }
            std::string decryptWithAAD(const std::string_view& aesKey, const std::string_view& data, const std::string_view &aad) {
                return aesDecryptWithAAD("AES-GCM", aesKey, data, aad);
            }
            std::string decryptFromHexWithAAD(const std::string_view& aesKey, const std::string_view& data, const std::string_view &aad) {
                return aesDecryptFromHexWithAAD("AES-GCM", aesKey, data, aad);
            }
            std::string decryptFromBase64WithAAD(const std::string_view& aesKey, const std::string_view& data, const std::string_view &aad) {
                return aesDecryptFromBase64WithAAD("AES-GCM", aesKey, data, aad);
            }

        }

        namespace AESECBUtils {
            std::string encrypt(const std::string_view& aesKey, const std::string_view& data) {
                return aesEncrypt("AES-ECB", aesKey, data);
            }
            std::string encryptToHex(const std::string_view& aesKey, const std::string_view& data) {
                return aesEncryptToHex("AES-ECB", aesKey, data);
            }
            std::string encryptToBase64(const std::string_view& aesKey, const std::string_view& data) {
                return aesEncryptToBase64("AES-ECB", aesKey, data);
            }
            std::string decrypt(const std::string_view& aesKey, const std::string_view& data) {
                return aesDecrypt("AES-ECB", aesKey, data);
            }
            std::string decryptFromHex(const std::string_view& aesKey, const std::string_view& data) {
                return aesDecryptFromHex("AES-ECB", aesKey, data);
            }
            std::string decryptFromBase64(const std::string_view& aesKey, const std::string_view& data) {
                return aesDecryptFromBase64("AES-ECB", aesKey, data);
            }
        }

    }
}