//
// Created by baojian on 2025/8/21.
//

#include "sm4.h"
#include "base64.h"
#include "config.h"
#include "hex.h"
#include <openssl/rand.h>
#include <iostream>

#include "openssl/core_names.h"

namespace camel {
    namespace crypto {
        SM4KeyGenerator::SM4KeyGenerator(int keyBitLength) {
            this->mKeyBitLength = keyBitLength;
            this->secretKey.resize(keyBitLength/8);
            unsigned char * buffer = (unsigned char *)secretKey.data();
            if (RAND_priv_bytes(buffer, secretKey.size()) != 1) {
                std::cerr << "SM4KeyGenerator::SM4KeyGenerator() RAND_priv_bytes() failed" << std::endl;
                printOpenSSLError();
                secretKey = "";
            }
        }

        std::string SM4KeyGenerator::getKey() {
            return secretKey;
        }

        std::string SM4KeyGenerator::getHexKey() {
            return hex_encode(secretKey);
        }


        std::string SM4KeyGenerator::getBase64Key() {
            return base64_encode(secretKey);
        }

    }
}


namespace camel {
    namespace crypto {
        std::string getSM4Key(const std::string_view& secret, const std::string_view& format) {
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

        inline bool SM4AlgorithmHas(const std::string& algorithm, std::string_view target) {
            return algorithm.find(target) != std::string::npos;
        }

        inline std::string SM4Name(const int keyBitLength, const std::string& mode) {
            std::string name = "SM4-";
            if (keyBitLength == 256) {
                //name.append("256");
            } else if (keyBitLength== 192) {
               // name.append("192");
            } else {
                //name.append("128");
            }
            //name.append("-");
            name.append(mode);
            return name;
        }

        inline bool isSM4KeyBitLenNotValid(const int keyBitLength) {
            return !(keyBitLength == 256
                     || keyBitLength == 192
                     || keyBitLength == 128);
        }


        /**
        * 模式为 ECB	无需 IV（ECB 是独立分组加密，无链式依赖）
        * 模式为 CFB/OFB/CTR/CTS	无需填充（流式 / 特殊分组模式，明文长度无需对齐 SM4 分组（16 字节））
        * 其他模式（如 CBC）	需 IV + PKCS#7 填充（默认填充方式）
         * @param plainData
         * @param secretKey
         * @return
         */
        std::string SM4_normal_encrypt(const std::string_view &plainData, const std::string& secretKey, const std::string& mode) {
            if (isSM4KeyBitLenNotValid(secretKey.size()*8)) {
                std::cerr << "SM4_normal_encrypt secretKey size invalid" << std::endl;
                return "";
            }
            EVP_CIPHER_CTX *ctx = nullptr;
            EVP_CIPHER *cipher = nullptr;
            ctx = EVP_CIPHER_CTX_new();
            if (ctx == nullptr) {
                std::cerr << "SM4_normal_encrypt EVP_CIPHER_CTX_new() failed" << std::endl;
                printOpenSSLError();
                return "";
            }
            std::string algorithmName = SM4Name(secretKey.length()*8, mode);

            cipher = EVP_CIPHER_fetch(nullptr, algorithmName.data(), nullptr);
            if (cipher == nullptr) {
                std::cerr << "SM4_normal_encrypt EVP_CIPHER_fetch() failed"  << algorithmName  << std::endl;
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
                size_t SM4_iv_len = 16;
                unsigned char* iv = (unsigned char* )combineBuffer.data();
                if (RAND_bytes(iv, SM4_iv_len) != 1) {
                    std::cerr << "SM4_normal_encrypt RAND_bytes() failed" << std::endl;
                    printOpenSSLError();
                    EVP_CIPHER_free(cipher);
                    EVP_CIPHER_CTX_free(ctx);
                    return "";
                }

                OSSL_PARAM params[] = {
                    OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_IVLEN,
                                            &SM4_iv_len),
                    OSSL_PARAM_END
                };
                const unsigned char *key = (const unsigned char *)secretKey.data();
                if (!EVP_EncryptInit_ex2(ctx, cipher, key, iv, params)) {
                    std::cerr << "SM4_normal_encrypt EVP_EncryptInit_ex2() failed" << std::endl;
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
                    std::cerr << "SM4_normal_encrypt EVP_EncryptInit_ex2() failed" << std::endl;
                    printOpenSSLError();
                    EVP_CIPHER_free(cipher);
                    EVP_CIPHER_CTX_free(ctx);
                    return "";
                }
            }
            if (needPadding) {
                if (!EVP_CIPHER_CTX_set_padding(ctx, 1)) {
                    std::cerr << "SM4_normal_encrypt EVP_CIPHER_CTX_set_padding failed" << std::endl;
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
                    std::cerr << "SM4_normal_encrypt Invalid IV length for SM4-CBC: must be 16 bytes" << std::endl;
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
                std::cerr << "SM4_normal_encryptEVP_EncryptUpdate() failed" << std::endl;
                printOpenSSLError();
                EVP_CIPHER_free(cipher);
                EVP_CIPHER_CTX_free(ctx);
                return "";
            }
            totalLen += outl;
            int tempLen = combineBuffer.size() - ivLength - outl;
            if (!EVP_EncryptFinal_ex(ctx, out + outl, &tempLen)) {
                std::cerr << "SM4_normal_encrypt EVP_EncryptFinal_ex() failed" << std::endl;
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
        std::string SM4_normal_decrypt(const std::string_view &encryptData, const std::string& secretKey, const std::string& mode) {
            if (isSM4KeyBitLenNotValid(secretKey.size()*8)) {
                std::cerr << "SM4_normal_decrypt secretKey size invalid" << std::endl;
                return "";
            }
            EVP_CIPHER_CTX *ctx = nullptr;
            EVP_CIPHER *cipher = nullptr;
            ctx = EVP_CIPHER_CTX_new();
            if (ctx == nullptr) {
                std::cerr << "SM4_normal_decrypt EVP_CIPHER_CTX_new() failed" << std::endl;
                printOpenSSLError();
                return "";
            }
            std::string algorithmName = SM4Name(secretKey.length()*8, mode);

            cipher = EVP_CIPHER_fetch(nullptr, algorithmName.data(), nullptr);
            if (cipher == nullptr) {
                std::cerr << "SM4_normal_decrypt EVP_CIPHER_fetch() failed " << algorithmName << std::endl;
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
                    std::cerr << "SM4_normal_decrypt illegal, encryptData too short " << std::endl;
                    return "";
                }
                OSSL_PARAM params[] = {
                    OSSL_PARAM_END
                };
                const unsigned char *key = (const unsigned char *)secretKey.data();
                const unsigned char *iv = (const unsigned char *)encryptData.data();
                if (!EVP_DecryptInit_ex2(ctx, cipher, key, iv, params)) {
                    std::cerr << "SM4_normal_decrypt EVP_DecryptInit_ex2() failed" << std::endl;
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
                    std::cerr << "aSM4_normal_decrypt EVP_DecryptInit_ex2() failed" << std::endl;
                    printOpenSSLError();
                    EVP_CIPHER_free(cipher);
                    EVP_CIPHER_CTX_free(ctx);
                    return "";
                }
            }
            if (needPadding) {
                if (!EVP_CIPHER_CTX_set_padding(ctx, 1)) {
                    std::cerr << "SM4_normal_decrypt EVP_CIPHER_CTX_set_padding failed" << std::endl;
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
                    std::cerr << "SM4_normal_decrypt Invalid IV length for SM4-CBC: must be 16 bytes" << std::endl;
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
                std::cerr << "SM4_normal_decrypt EVP_DecryptUpdate() failed" << std::endl;
                printOpenSSLError();
                EVP_CIPHER_free(cipher);
                EVP_CIPHER_CTX_free(ctx);
                return "";
            }
            totalLen += outl;
            int tempLen = buffer.size() - outl;
            if (!EVP_DecryptFinal_ex(ctx, out + outl, &tempLen)) {
                std::cerr << "SM4_normal_decrypt EVP_DecryptFinal_ex() failed" << std::endl;
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
         std::string SM4_gcm_ccm_encrypt(const std::string_view &plainData,
            const std::string& secretKey,
            const std::string& mode,
            const std::string_view &aad) {
            if (isSM4KeyBitLenNotValid(secretKey.size()*8)) {
                std::cerr << "SM4_gcm_ccm_encrypt secretKey size invalid " << std::endl;
                return "";
            }

            int gcm_iv_len = 12; // ccm模式的once
            int gcm_tag_len = 16; // ccm的tag

            EVP_CIPHER_CTX *ctx = nullptr;
            EVP_CIPHER *cipher = nullptr;
            ctx = EVP_CIPHER_CTX_new();
            if (ctx == nullptr) {
                std::cerr << "SM4_gcm_ccm_encrypt EVP_CIPHER_CTX_new() failed" << std::endl;
                printOpenSSLError();
                return "";
            }
            std::string algorithmName = SM4Name(secretKey.length()*8, mode);

            cipher = EVP_CIPHER_fetch(nullptr, algorithmName.data(), nullptr);
            if (cipher == nullptr) {
                std::cerr << "SM4_gcm_ccm_encrypt EVP_CIPHER_fetch() failed" << std::endl;
                printOpenSSLError();
                EVP_CIPHER_CTX_free(ctx);
                return "";
            }
            std::string combineBuffer; // iv + buffer + tag
            combineBuffer.resize(std::max((int)plainData.size()*2 + 64, 512));

            { // init ctx
                unsigned char* iv = (unsigned char* )combineBuffer.data();
                if (RAND_bytes(iv, gcm_iv_len) != 1) {
                    std::cerr << "SM4_gcm_ccm_encrypt RAND_bytes() failed" << std::endl;
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
                if (SM4AlgorithmHas(algorithmName, "CCM")) { //CCM模式需要设置tag
                    params[1] =  OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG,
                                                  NULL, gcm_tag_len);
                }
                const unsigned char *key = (const unsigned char *)secretKey.data();
                /*
                 * Initialise encrypt operation with the cipher & mode,
                 * nonce/iv length and tag length parameters.
                 */
                if (!EVP_EncryptInit_ex2(ctx, cipher, nullptr, nullptr, params)) {
                    std::cerr << "SM4_gcm_ccm_encrypt EVP_EncryptInit_ex2() failed" << std::endl;
                    printOpenSSLError();
                    EVP_CIPHER_free(cipher);
                    EVP_CIPHER_CTX_free(ctx);
                    return "";
                }
                // 分两步初始化，参考解密
                /* Initialise key and nonce/iv */
                if (!EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) {
                    std::cerr << "SM4_gcm_ccm_encrypt EVP_EncryptInit_ex() failed" << std::endl;
                    printOpenSSLError();
                    EVP_CIPHER_free(cipher);
                    EVP_CIPHER_CTX_free(ctx);
                    return "";
                }
            }


            int ivLength = EVP_CIPHER_get_iv_length(cipher);
            if (ivLength != gcm_iv_len) {
                std::cerr << "SM4_gcm_ccm_encrypt Invalid IV length for SM4-GCM: must be 12 bytes"  << ivLength << std::endl;
                EVP_CIPHER_free(cipher);
                EVP_CIPHER_CTX_free(ctx);
                return "";
            }

            if (!aad.empty()) {
                int outlen;
                const unsigned char *aadIn = (const unsigned char *)aad.data();
                if (!EVP_EncryptUpdate(ctx, NULL, &outlen, aadIn, aad.size())) {
                    std::cerr << "SM4_gcm_ccm_encrypt EVP_EncryptUpdate() aad failed" << std::endl;
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
                std::cerr << "SM4_gcm_ccm_encrypt EVP_EncryptUpdate() failed" << std::endl;
                printOpenSSLError();
                EVP_CIPHER_free(cipher);
                EVP_CIPHER_CTX_free(ctx);
                return "";
            }
            totalLen += outl;

            int tempLen = combineBuffer.size() - gcm_iv_len - gcm_tag_len - outl;
            if (!EVP_EncryptFinal_ex(ctx, out + outl, &tempLen)) {
                std::cerr << "SM4_gcm_ccm_encrypt EVP_EncryptFinal_ex() failed" << std::endl;
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
                std::cerr << "SM4_gcm_ccm_encrypt EVP_CIPHER_CTX_get_params() failed " << algorithmName << std::endl;
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

        std::string SM4_gcm_ccm_decrypt(const std::string_view &encryptData,
            const std::string& secretKey,
            const std::string& mode,
            const std::string_view &aad) {

            if (isSM4KeyBitLenNotValid(secretKey.size()*8)) {
                std::cerr << "SM4_gcm_ccm_decrypt secretKey size invalid" << std::endl;
                return "";
            }
            size_t gcm_iv_len = 12; // ccm模式的once
            size_t gcm_tag_len = 16; // ccm的tag
            if (encryptData.size() <= (gcm_iv_len + gcm_tag_len)) {
                std::cerr << "SM4_gcm_ccm_decrypt illegal, encryptData too short " << std::endl;
                return "";
            }
            EVP_CIPHER_CTX *ctx = nullptr;
            EVP_CIPHER *cipher = nullptr;
            ctx = EVP_CIPHER_CTX_new();
            if (ctx == nullptr) {
                std::cerr << "SM4_gcm_ccm_decrypt EVP_CIPHER_CTX_new() failed" << std::endl;
                printOpenSSLError();
                return "";
            }
            std::string algorithmName = SM4Name(secretKey.length()*8, mode);

            cipher = EVP_CIPHER_fetch(nullptr, algorithmName.data(), nullptr);
            if (cipher == nullptr) {
                std::cerr << "SM4_gcm_ccm_decrypt EVP_CIPHER_fetch() failed" << std::endl;
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
                    std::cerr << "SM4_gcm_ccm_decrypt EVP_DecryptInit_ex2() failed" << std::endl;
                    printOpenSSLError();
                    EVP_CIPHER_free(cipher);
                    EVP_CIPHER_CTX_free(ctx);
                    return "";
                }
                //CCM 模式分两步初始化，不然解密不成功，这种写法来自官方demo。
                /* Initialise key and nonce/iv */
                if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) {
                    std::cerr << "SM4_gcm_ccm_decrypt EVP_DecryptInit_ex() failed" << std::endl;
                    printOpenSSLError();
                    EVP_CIPHER_free(cipher);
                    EVP_CIPHER_CTX_free(ctx);
                    return "";
                }
            }


            int ivLength = EVP_CIPHER_get_iv_length(cipher);
            if (ivLength != gcm_iv_len) {
                std::cerr << "SM4_gcm_ccm_decrypt Invalid IV length for SM4-GCM: must be 12 bytes" << std::endl;
                EVP_CIPHER_free(cipher);
                EVP_CIPHER_CTX_free(ctx);
                return "";
            }

            if (!aad.empty()) {
                int outlen;
                const unsigned char *aadIn = (const unsigned char *)aad.data();
                if (!EVP_DecryptUpdate(ctx, NULL, &outlen, aadIn, aad.size())) {
                    std::cerr << "SM4_gcm_ccm_decrypt EVP_DecryptUpdate() aad failed" << std::endl;
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
                std::cerr << "SM4_gcm_ccm_decrypt EVP_DecryptUpdate() failed" << std::endl;
                printOpenSSLError();
                EVP_CIPHER_free(cipher);
                EVP_CIPHER_CTX_free(ctx);
                return "";
            }
            totalLen += outl;

            int tempLen = buffer.size() - outl;
            if (!EVP_DecryptFinal_ex(ctx, out + outl, &tempLen)) {
                std::cerr << "SM4_gcm_ccm_decrypt EVP_DecryptFinal_ex() failed" << std::endl;
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
         SM4Encryptor::SM4Encryptor(const std::string& algorithm, const std::string_view& secret, const std::string& format) {
            this->algorithm = algorithm;
            this->secretKey = getSM4Key(secret, format);
        }

        std::string SM4Encryptor::encrypt(const std::string_view &plainText) const {
            if (SM4AlgorithmHas(algorithm, "CBC")) {
                return SM4_normal_encrypt(plainText, secretKey, "CBC");
            }
            if (SM4AlgorithmHas(algorithm, "CFB")) {
                return SM4_normal_encrypt(plainText, secretKey, "CFB");
            }
            if (SM4AlgorithmHas(algorithm, "CTR")) {
                return SM4_normal_encrypt(plainText,  secretKey, "CTR");
            }
            if (SM4AlgorithmHas(algorithm, "CTS")) {
                std::cerr << "SM4Decryptor::decrypt CTS not support, please use SM4-CBC" << std::endl;
                return "";
            }

            if (SM4AlgorithmHas(algorithm, "ECB")) {
                return SM4_normal_encrypt(plainText, secretKey, "ECB");
            }

            if (SM4AlgorithmHas(algorithm, "OFB")) {
                return SM4_normal_encrypt(plainText, secretKey, "OFB");
            }
            if (SM4AlgorithmHas(algorithm, "GCM-SIV")) {
                std::cerr << "SM4Encryptor::encrypt() not supported algorithm " << algorithm << std::endl;
                return "";
            }

            if (SM4AlgorithmHas(algorithm, "GCM")) {
                return SM4_gcm_ccm_encrypt(plainText,  secretKey, "GCM", "");
            }
            if (SM4AlgorithmHas(algorithm, "CCM")) {
                return SM4_gcm_ccm_encrypt(plainText, secretKey, "CCM", "");
            }

            if (SM4AlgorithmHas(algorithm, "SM4-SIV") || SM4AlgorithmHas(algorithm, "SM4/SIV")) {
                std::cerr << "SM4Encryptor::encrypt() not supported algorithm " << algorithm << std::endl;
                return "";
            }

            std::cerr << "SM4Encryptor::encrypt() not supported algorithm " << algorithm << std::endl;
            return "";
        }

        std::string SM4Encryptor::encryptToHex(const std::string_view &plainText) const {
            return hex_encode(encrypt(plainText));
        }


        std::string SM4Encryptor::encryptToBase64(const std::string_view &plainText) const {
            return base64_encode(encrypt(plainText));
        }

        std::string SM4Encryptor::encryptWithAAD(const std::string_view &plainText, const std::string_view &aad) const {
            if (SM4AlgorithmHas(algorithm, "GCM-SIV")) {
                std::cerr << "SM4Encryptor::encrypt() not supported algorithm " << algorithm << std::endl;
                return "";
            }

            if (SM4AlgorithmHas(algorithm, "GCM")) {
                return SM4_gcm_ccm_encrypt(plainText, secretKey, "GCM", aad);
            }
            if (SM4AlgorithmHas(algorithm, "CCM")) {
                return SM4_gcm_ccm_encrypt(plainText, secretKey, "CCM", aad);
            }
            if (SM4AlgorithmHas(algorithm, "SM4-SIV") || SM4AlgorithmHas(algorithm, "SM4/SIV")) {
                std::cerr << "SM4Encryptor::encrypt() not supported algorithm " << algorithm << std::endl;
                return "";
            }
            std::cerr << "SM4Encryptor::encryptWithAAD() not supported algorithm " << algorithm << std::endl;
            return "";
        }

        std::string SM4Encryptor::encryptToHexWithAAD(const std::string_view &plainText, const std::string_view &aad) const {
            return hex_encode(encryptWithAAD(plainText, aad));
        }

        std::string SM4Encryptor::encryptToBase64WithAAD(const std::string_view &plainText, const std::string_view &aad) const {
            return base64_encode(encryptWithAAD(plainText, aad));
        }
    }
}

namespace camel {
    namespace crypto {
         SM4Decryptor::SM4Decryptor(const std::string &algorithm, const std::string_view &secret, const std::string &format) {
            this->algorithm = algorithm;
            this->secretKey = getSM4Key(secret, format);
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
        std::string SM4Decryptor::decrypt(const std::string_view &encryptedData) const {
            if (SM4AlgorithmHas(algorithm, "CBC")) {
                return SM4_normal_decrypt(encryptedData, secretKey, "CBC");
            }
            if (SM4AlgorithmHas(algorithm, "CFB")) {
                return SM4_normal_decrypt(encryptedData, secretKey, "CFB");
            }
            if (SM4AlgorithmHas(algorithm, "CTR")) {
                return SM4_normal_decrypt(encryptedData, secretKey, "CTR");
            }
            if (SM4AlgorithmHas(algorithm, "CTS")) {
                std::cerr << "SM4Decryptor::decrypt CTS not support, please use SM4-CBC" << std::endl;
                return "";
            }

            if (SM4AlgorithmHas(algorithm, "ECB")) {
                return SM4_normal_decrypt(encryptedData, secretKey, "ECB");
            }

            if (SM4AlgorithmHas(algorithm, "OFB")) {
                return SM4_normal_decrypt(encryptedData, secretKey, "OFB");
            }

            if (SM4AlgorithmHas(algorithm, "GCM-SIV")) {
                std::cerr << "SM4Decryptor::decrypt() not supported algorithm " << algorithm << std::endl;
                return "";
            }

            if (SM4AlgorithmHas(algorithm, "GCM")) {
                return SM4_gcm_ccm_decrypt(encryptedData, secretKey, "GCM", "");
            }
            if (SM4AlgorithmHas(algorithm, "CCM")) {
                return SM4_gcm_ccm_decrypt(encryptedData, secretKey, "CCM", "");
            }

            if (SM4AlgorithmHas(algorithm, "SM4-SIV") || SM4AlgorithmHas(algorithm, "SM4/SIV")) {
                std::cerr << "SM4Decryptor::decrypt() not supported algorithm " << algorithm << std::endl;
                return "";
            }

            std::cerr << "SM4Decryptor::decrypt() not supported algorithm " << algorithm << std::endl;
            return "";
        }

        std::string SM4Decryptor::decryptFromHex(const std::string_view &hexEncryptedText) const {
            return decrypt(hex_decode(hexEncryptedText));
        }

        std::string SM4Decryptor::decryptFromBase64(const std::string_view &base64EncryptedText) const {
            return decrypt(base64_decode(base64EncryptedText));
        }

        std::string SM4Decryptor::decryptWithAAD(const std::string_view &encryptedData, const std::string_view &aad) const {
            if (SM4AlgorithmHas(algorithm, "GCM-SIV")) {
                std::cerr << "SM4Decryptor::decrypt() not supported algorithm " << algorithm << std::endl;
                return "";
            }

            if (SM4AlgorithmHas(algorithm, "GCM")) {
                return SM4_gcm_ccm_decrypt(encryptedData, secretKey, "GCM", aad);
            }
            if (SM4AlgorithmHas(algorithm, "CCM")) {
                return SM4_gcm_ccm_decrypt(encryptedData, secretKey, "CCM", aad);
            }
            if (SM4AlgorithmHas(algorithm, "SM4-SIV") || SM4AlgorithmHas(algorithm, "SM4/SIV")) {
                std::cerr << "SM4Decryptor::decrypt() not supported algorithm " << algorithm << std::endl;
                return "";
            }
            std::cerr << "SM4Decryptor::decryptWithAAD() not supported algorithm " << algorithm << std::endl;
            return "";
        }

        std::string SM4Decryptor::decryptFromHexWithAAD(const std::string_view &encryptedData, const std::string_view &aad) const {
            return decryptWithAAD(hex_decode(encryptedData), aad);
        }

        std::string SM4Decryptor::decryptFromBase64WithAAD(const std::string_view &encryptedData, const std::string_view &aad) const {
            return decryptWithAAD(base64_decode(encryptedData), aad);
        }

    }
}