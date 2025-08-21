//
// Created by efurture on 25-8-19.
//

#ifndef CAMEL_SM2_H
#define CAMEL_SM2_H
#include <string>

#include "openssl/evp.h"
#include "openssl/types.h"

namespace camel {
    namespace crypto {

        class SM2KeyPairGenerator {
        public:
            explicit SM2KeyPairGenerator();
            ~SM2KeyPairGenerator();
        public:
            std::string getPublicKey();
            std::string getPrivateKey();
            std::string getHexPublicKey();
            std::string getHexPrivateKey();
            std::string getBase64NewLinePublicKey();  //same with pem
            std::string getBase64NewLinePrivateKey(); //same with pem
            std::string getBase64PublicKey();
            std::string getBase64PrivateKey();
            std::string getPemPublicKey();
            std::string getPemPrivateKey();
        public:
            SM2KeyPairGenerator(const SM2KeyPairGenerator&) = delete;
            SM2KeyPairGenerator& operator=(const SM2KeyPairGenerator&) = delete;
        private:
            void createSM2KeyPair();
            void clean();
        private:
            EVP_PKEY_CTX* ctx = nullptr;
            EVP_PKEY* pkey = nullptr;
        };
    }
}


namespace camel {
    namespace crypto {
        EVP_PKEY* SM2PublicKeyFromPem(const std::string& pemKey);
        EVP_PKEY* SM2PublicKeyFromBase64(const std::string& base64Key);
        EVP_PKEY* SM2PublicKeyFromHex(const std::string& hexKey);
        EVP_PKEY* SM2PublicKeyFromDer(const std::string& derKey);
        EVP_PKEY* SM2PublicKeyFromDerByBio(const std::string& derKey);
        EVP_PKEY* SM2PublicKeyFrom(const std::string& publicKey, const std::string& format);

        EVP_PKEY* SM2PrivateKeyFromPem(const std::string& pemKey);
        EVP_PKEY* SM2PrivateKeyFromBase64(const std::string& base64Key);
        EVP_PKEY* SM2PrivateKeyFromHex(const std::string& hexKey);
        EVP_PKEY* SM2PrivateKeyFromDer(const std::string& derKey);
        EVP_PKEY* SM2PrivateKeyFromDerByBio(const std::string& derKey);
        EVP_PKEY* SM2PrivateKeyFrom(const std::string& privateKey, const std::string& format);

        inline void freeSM2EvpKey(EVP_PKEY* key) {
            if (key != nullptr) {
                EVP_PKEY_free(key);
            }
        }
        std::string sm2_java_c1_c2_c3_to_OpenSSL_ASN1_Format(const std::string_view& javaData);
        std::string sm2_java_c1_c3_c2_to_OpenSSL_ASN1_Format(const std::string_view& javaData);

        std::string sm2_ASN1_to_java_c1_c3_c2_Format(const std::string_view& asn1Data);
        std::string sm2_ASN1_to_java_c1_c2_c3_Format(const std::string_view& asn1Data);
    }
}


namespace camel {
    namespace crypto {
        class SM2PublicKeyEncryptor {
        public:
            /**
             * https://developer.android.com/reference/javax/crypto/Cipher
            * format = "pem", "hex", "base64", "der"
             */
            explicit SM2PublicKeyEncryptor(const std::string_view& publicKey,
                 const std::string_view& format = "pem", const std::string_view& dataModeFlag = "ANS1");

            ~SM2PublicKeyEncryptor() = default;

        public:
            std::string encrypt(const std::string_view& plainText) const;
            std::string encryptToBase64(const std::string_view& plainText) const;
            std::string encryptToHex(const std::string_view& plainText) const;
        public:
            /**
             * 外部提供的EVP_PKEY指针，如果指定则不再加载默认秘钥.不指定则，加载默认秘钥
             *  外部自己负责释放，管理EVP_PKEY生命周期，用于复用EVP_PKEY秘钥，避免重复加载，高性能等场景。
             *  有效提升加密性能，可多个Encryptor通setExternalEvpKey设置相同共用，显著提升性能。
             * @param pkey
             */
            void setExternalEvpKey(EVP_PKEY* pkey) {
                this->externalEvpKey = pkey;
            }
           /**
           * 设置加密密数据格式：ANS1 C1C2C3 C1C3C2
           * @param modeFlag
           */
            void setDataModeFlag(const std::string& modeFlag) {
                this->dataModeFlag = modeFlag;
            }
        private:
            std::string publicKey;
            std::string format;
            std::string dataModeFlag; //输出格式 ANS1 C1C2C3 C1C3C2  解密JAVA数据时格式 C1 C2 C3 还是 C1 C3 C2. 默认ANS1，如果不是自动用C1 C2 C3格式转换
        private:
            EVP_PKEY* externalEvpKey = nullptr; //外部key，外部自己管理生命周期。
        };
    }
}

namespace camel {
    namespace crypto {
        class SM2PrivateKeyDecryptor {
        public:
            explicit SM2PrivateKeyDecryptor(const std::string_view& privateKey,
                  const std::string_view& format = "pem",
                  const std::string_view& dataModeFlag = "ANS1");
            ~SM2PrivateKeyDecryptor() = default;
        public:
            SM2PrivateKeyDecryptor(const SM2PrivateKeyDecryptor&) = delete;
            SM2PrivateKeyDecryptor& operator=(const SM2PrivateKeyDecryptor&) = delete;
        public:
            std::string decrypt(const std::string_view& encryptedData);
            std::string decryptFromBase64(const std::string_view& base64EncryptedText);
            std::string decryptFromHex(const std::string_view& hexEncryptedText);
        public:
            /**
             * 外部提供的EVP_PKEY指针，如果指定则不再加载默认秘钥.不指定则，加载默认秘钥
             *  外部自己负责释放，管理EVP_PKEY生命周期，用于复用EVP_PKEY秘钥，避免重复加载，高性能等场景
             * @param pkey
             */
            void setExternalEvpKey(EVP_PKEY* pkey) {
                this->externalEvpKey = pkey;
            }

            /**
             * 设置解密数据格式：ANS1 C1C2C3 C1C3C2
             * @param modeFlag
             */
            void setDataModeFlag(const std::string& modeFlag) {
                this->dataModeFlag = modeFlag;
            }
        private:
            std::string privateKey;
            std::string format;
            std::string dataModeFlag; // ANS1 C1C2C3 C1C3C2  解密JAVA数据时格式 C1 C2 C3 还是 C1 C3 C2. 默认ANS1，如果不是自动用C1 C2 C3格式转换
        private:
            EVP_PKEY* externalEvpKey = nullptr; //外部key，外部自己管理生命周期。
        };
    }
}

namespace camel {
    namespace crypto {
        class SM2PrivateKeySigner {
        public:
            /** SM3withSM2 签名，目前默认这种算法。
              * format = "pem", "hex", "base64", "der"
              * sm2UserId 1234567812345678
               */
            explicit SM2PrivateKeySigner(const std::string_view& privateKey,
                  const std::string_view& format = "pem",
                  const std::string_view& sm2UserId = "1234567812345678");
            ~SM2PrivateKeySigner() = default;
        public:
            SM2PrivateKeySigner(const SM2PrivateKeySigner&) = delete;
            SM2PrivateKeySigner& operator=(const SM2PrivateKeySigner&) = delete;
        public:
            std::string sign(const std::string_view& plainText) const;
            std::string signToBase64(const std::string_view& plainText) const;
            std::string signToHex(const std::string_view& plainText) const;
        public:
            /**
             * 外部提供的EVP_PKEY指针，如果指定则不再加载默认秘钥.不指定则，加载默认秘钥
             *  外部自己负责释放，管理EVP_PKEY生命周期，用于复用EVP_PKEY秘钥，避免重复加载，高性能等场景
             * @param pkey
             */
            void setExternalEvpKey(EVP_PKEY* pkey) {
                this->externalEvpKey = pkey;
            }
            //设置签名的userId
            void setSM2UserId(const std::string_view& userId) {
                this->sm2UserId = userId;
            }
        private:
            std::string privateKey;
            std::string format;
            std::string sm2UserId; // UTF-8编码的userId, 长度小于8192字节
        private:
            EVP_PKEY* externalEvpKey = nullptr; //外部key，外部自己管理生命周期。
        };
    }
}


namespace camel {
    namespace crypto {
         class SM2PublicKeyVerifier{
        public:
             /** SM3withSM2 签名，目前默认这种算法。
               * format = "pem", "hex", "base64", "der"
               * sm2UserId 1234567812345678
                */
            explicit SM2PublicKeyVerifier(const std::string_view& publicKey,
                  const std::string_view& format = "pem",
                  const std::string_view& sm2UserId = "1234567812345678");
            ~SM2PublicKeyVerifier() = default;
        public:
             bool verifySign(const std::string_view& sign, const std::string_view& data) const;
             bool verifyHexSign(const std::string_view& hexSign, const std::string_view& data) const;
             bool verifyBase64Sign(const std::string_view& base64Sign, const std::string_view& data) const;
        public:
            /**
             * 外部提供的EVP_PKEY指针，如果指定则不再加载默认秘钥.不指定则，加载默认秘钥
             *  外部自己负责释放，管理EVP_PKEY生命周期，用于复用EVP_PKEY秘钥，避免重复加载，高性能等场景
             * @param pkey
             */
            void setExternalEvpKey(EVP_PKEY* pkey) {
                this->externalEvpKey = pkey;
            }
             void setSM2UserId(const std::string_view& userId) {
                this->sm2UserId = userId;
            }
        private:
            std::string publicKey;
            std::string format;
            std::string sm2UserId; // UTF-8编码的userId, 长度小于8192字节
        private:
            EVP_PKEY* externalEvpKey = nullptr; //外部key，外部自己管理生命周期。
        };

    }
}

#endif //CAMEL_SM2_H
