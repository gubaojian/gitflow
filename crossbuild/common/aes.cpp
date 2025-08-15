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

        /**
         *
         * @param encryptData
         * @param secretKey
         * @return
         */
        std::string aes_normal_decrypt(const std::string_view &encryptData, const std::string& secretKey, const std::string& mode) {
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
                    std::cerr << "aes_ecb_decrypt EVP_DecryptInit_ex2() failed" << std::endl;
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

        std::string aes_gcm_ccm_decrypt(const std::string_view &encryptData,
            const std::string& secretKey,
            const std::string& mode,
            const std::string_view &aad) {
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
            const int siv_iv_length = 16; // iv(tag) + buffer
            std::string combineBuffer; // iv(tag) + buffer
            combineBuffer.resize(std::max((int)plainData.size()*2 + 32, 512));

            {
                unsigned char* iv = (unsigned char* )combineBuffer.data();
                if (RAND_bytes(iv, siv_iv_length) != 1) {
                    std::cerr << "aes_siv_encrypt RAND_bytes() failed" << std::endl;
                    printOpenSSLError();
                    EVP_CIPHER_free(cipher);
                    EVP_CIPHER_CTX_free(ctx);
                    return "";
                }

                const unsigned char *key = (const unsigned char *)secretKey.data();
                OSSL_PARAM params[] = {
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

                for (int i = 0; i < 16; i++) {
                    std::cout << "key = " << key[i] << ", iv = " << iv[i] << std::endl;
                }

                /* Initialise key and nonce/iv */
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
        AESEncryptor::AESEncryptor(const std::string& algorithm, const std::string& secret, const std::string& format) {
            this->algorithm = algorithm;
            if (format == "base64") {
                this->secretKey = base64_decode(secret);
            } else if (format == "hex") {
                this->secretKey = hex_decode(secret);
            }  else if (format == "binary" || format == "raw") {
                this->secretKey = secret;
            } else {
                this->secretKey = secret;
            }
        }

        std::string AESEncryptor::encrypt(const std::string_view &plainText) const {
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



    }
}

namespace camel {
    namespace crypto {
        AESDecryptor::AESDecryptor(const std::string &algorithm, const std::string &secret, const std::string &format) {
            this->algorithm = algorithm;
            if (format == "base64") {
                this->secretKey = base64_decode(secret);
            } else if (format == "hex") {
                this->secretKey = hex_decode(secret);
            }  else if (format == "binary" || format == "raw") {
                this->secretKey = secret;
            } else {
                this->secretKey = secret;
            }
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