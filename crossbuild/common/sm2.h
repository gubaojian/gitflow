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
                 const std::string_view& format = "pem", const std::string_view& algorithm = "AES-256-GCM");

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
        private:
            std::string publicKey;
            std::string format;
            std::string algorithm;
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
                  const std::string_view& algorithm = "");
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
        private:
            std::string privateKey;
            std::string format;
            std::string algorithm;
        private:
            EVP_PKEY* externalEvpKey = nullptr; //外部key，外部自己管理生命周期。
        };
    }
}

#endif //CAMEL_SM2_H
