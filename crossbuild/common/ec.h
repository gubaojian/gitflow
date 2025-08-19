//
// Created by baojian on 2025/8/18.
//

#ifndef CAMEL_ELLIPTIC_CURVE_H
#define CAMEL_ELLIPTIC_CURVE_H
#include <string>
#include <string_view>
#include <openssl/types.h>

#include "openssl/evp.h"

namespace camel {
    namespace crypto {

        EVP_PKEY* ECPublicKeyFromPem(const std::string& pemKey);
        EVP_PKEY* ECPublicKeyFromBase64(const std::string& base64Key);
        EVP_PKEY* ECPublicKeyFromHex(const std::string& hexKey);
        EVP_PKEY* ECPublicKeyFromDer(const std::string& derKey);
        EVP_PKEY* ECPublicKeyFromDerByBio(const std::string& derKey);
        EVP_PKEY* ECPublicKeyFrom(const std::string& publicKey, const std::string& format);

        EVP_PKEY* ECPrivateKeyFromPem(const std::string& pemKey);
        EVP_PKEY* ECPrivateKeyFromBase64(const std::string& base64Key);
        EVP_PKEY* ECPrivateKeyFromHex(const std::string& hexKey);
        EVP_PKEY* ECPrivateKeyFromDer(const std::string& derKey);
        EVP_PKEY* ECPrivateKeyFromDerByBio(const std::string& derKey);
        EVP_PKEY* ECPrivateKeyFrom(const std::string& privateKey, const std::string& format);

        inline void freeECEvpKey(EVP_PKEY* key) {
            if (key != nullptr) {
                EVP_PKEY_free(key);
            }
        }

        class ECKeyPairGenerator {
        public:
            /**
             * openssl ecparam -list_curves 查看所有支持的
            *  代码兼容 OpenSSL 支持的所有椭圆曲线，包括：
            *  NIST 曲线：secp256r1（P-256）、secp384r1（P-384）、secp521r1（P-521）
            *  区块链常用：secp256k1
            *  Edwards 曲线：ed25519、x25519、ed448、x448
            *  国密曲线：SM2（需 OpenSSL 支持国密算法）
             *  ecp256r1 secp284r1 ed25519 secp256k1 SM2  x25519 ed448
             */
            explicit ECKeyPairGenerator(const std::string_view& curveName = "secp256r1");
            ~ECKeyPairGenerator();
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
            ECKeyPairGenerator(const ECKeyPairGenerator&) = delete;
            ECKeyPairGenerator& operator=(const ECKeyPairGenerator&) = delete;
        private:
            void clean();
        private:
            EVP_PKEY_CTX* ctx = nullptr;
            EVP_PKEY* pkey = nullptr;
            std::string curveName;
        };

        class ECPublicKeyEncryptor {
        public:
            /**
             * https://developer.android.com/reference/javax/crypto/Cipher
            * format = "pem", "hex", "base64", "der"
             */
            explicit ECPublicKeyEncryptor(const std::string_view& publicKey,
                 const std::string_view& format = "pem", const std::string_view& algorithm = "AES-256-GCM");

            ~ECPublicKeyEncryptor() = default;

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


#endif //CAMEL_ELLIPTIC_CURVE_H