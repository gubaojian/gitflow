//
// Created by baojian on 25-8-5.
//

#ifndef CAMEL_RSA_H
#define CAMEL_RSA_H
#include "config.h"
#include "hex.h"
#include "base64.h"
#include <string>
#include <openssl/types.h>


namespace camel {
    namespace crypto {


        EVP_PKEY* RSAPublicKeyFromPem(const std::string& pemKey);
        EVP_PKEY* RSAPublicKeyFromBase64(const std::string& base64Key);
        EVP_PKEY* RSAPublicKeyFromHex(const std::string& hexKey);
        EVP_PKEY* RSAPublicKeyFromDer(const std::string& derKey);
        EVP_PKEY* RSAPublicKeyFromDerByBio(const std::string& derKey);
        EVP_PKEY* RSAPublicKeyFrom(const std::string& publicKey, const std::string& format);

        EVP_PKEY* RSAPrivateKeyFromPem(const std::string& pemKey);
        EVP_PKEY* RSAPrivateKeyFromBase64(const std::string& base64Key);
        EVP_PKEY* RSAPrivateKeyFromHex(const std::string& hexKey);
        EVP_PKEY* RSAPrivateKeyFromDer(const std::string& derKey);
        EVP_PKEY* RSAPrivateKeyFromDerByBio(const std::string& derKey);
        EVP_PKEY* RSAPrivateKeyFrom(const std::string& privateKey, const std::string& format);


        class RSAKeyPairGenerator {
            public:
                explicit RSAKeyPairGenerator(int keyLength=2048); //1024 2048 4096
                ~RSAKeyPairGenerator();
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
                RSAKeyPairGenerator(const RSAKeyPairGenerator&) = delete;
                RSAKeyPairGenerator& operator=(const RSAKeyPairGenerator&) = delete;
             private:
                void clean();
          private:
            EVP_PKEY_CTX* ctx = nullptr;
            EVP_PKEY* pkey = nullptr;
        };



        constexpr auto  RSA_PKCS1Padding = "PKCS1Padding";
        constexpr auto  RSA_OAEPPadding = "OAEPPadding";
        constexpr auto  RSA_OAEPWithSHA_1AndMGF1Padding = " OAEPWithSHA-1AndMGF1Padding";
        constexpr auto  RSA_OAEPwithSHA_256andMGF1Padding = "OAEPwithSHA-256andMGF1Padding";
        constexpr auto  RSA_OAEPwithSHA_384andMGF1Padding = "OAEPwithSHA-384andMGF1Padding";
        constexpr auto  RSA_OAEPwithSHA_512andMGF1Padding = "OAEPwithSHA-512andMGF1Padding";
        constexpr auto  RSA_OAEP_SHA256_MGF1_SHA256 = "RSA_OAEP_SHA256_MGF1_SHA256";
        constexpr auto  RSA_OAEP_SHA512_MGF1_SHA512 = "RSA_OAEP_SHA512_MGF1_SHA512";
        constexpr auto  RSA_OAEP_SHA3_256_MGF1_SHA3_256 = "RSA_OAEP_SHA3_256_MGF1_SHA3_256";
        constexpr auto  RSA_OAEP_SHA3_512_MGF1_SHA3_512 = "RSA_OAEP_SHA3_512_MGF1_SHA3_512";

        class RSAPublicKeyEncryptor {
           public:
               /**
               * format = "pem", "hex", "base64", "der"
               * OAEPPadding PKCS1Padding default
               * OAEPwithSHA-256andMGF1Padding
               * OAEPwithSHA-384andMGF1Padding
               * OAEPwithSHA-512andMGF1Padding
                */
               explicit RSAPublicKeyEncryptor(const std::string& publicKey,
                    const std::string& format = "pem",
                    const std::string& paddings= RSA_PKCS1Padding);

               ~RSAPublicKeyEncryptor() = default;

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
              std::string paddings;
           private:
               EVP_PKEY* externalEvpKey = nullptr; //外部key，外部自己管理生命周期。
        };

        class RSAPrivateKeyDecryptor {
        public:
            /**
              * format = "pem", "hex", "base64", "der"
              * OAEPPadding PKCS1Padding default
              * OAEPwithSHA-256andMGF1Padding
              * OAEPwithSHA-384andMGF1Padding
              * OAEPwithSHA-512andMGF1Padding
               */
            explicit RSAPrivateKeyDecryptor(const std::string& privateKey,
                  const std::string& format = "pem",
                  const std::string& paddings = RSA_PKCS1Padding);
            ~RSAPrivateKeyDecryptor() = default;
        public:
            RSAPrivateKeyDecryptor(const RSAPrivateKeyDecryptor&) = delete;
            RSAPrivateKeyDecryptor& operator=(const RSAPrivateKeyDecryptor&) = delete;
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
            std::string paddings;
        private:
            EVP_PKEY* externalEvpKey = nullptr; //外部key，外部自己管理生命周期。
        };


        class RSAPrivateKeySigner {
        public:
            /**
              * format = "pem", "hex", "base64", "der"
              * algorithm
              * MD5withRSA SHA1withRSA SHA256withRSA SHA384withRSA SHA512withRSA
              * SHA512/224withRSA SHA512/256withRSA
              * SHA3_256withRSA SHA3_384withRSA SHA3_512withRSA
              *  or pre algorithm like  SHA384withRSA/PSS SHA256withRSA/PSS
               */
            explicit RSAPrivateKeySigner(const std::string& publicKey,
                  const std::string& format = "pem",
                  const std::string& algorithm = "SHA256withRSA");
            ~RSAPrivateKeySigner() = default;
        public:
            RSAPrivateKeySigner(const RSAPrivateKeySigner&) = delete;
            RSAPrivateKeySigner& operator=(const RSAPrivateKeySigner&) = delete;
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
        private:
            std::string privateKey;
            std::string format;
            std::string algorithm;
        private:
            EVP_PKEY* externalEvpKey = nullptr; //外部key，外部自己管理生命周期。
        };

        class RSAPublicKeyVerifier{
        public:
            /**
              * format = "pem", "hex", "base64", "der"
              * algorithm
              * MD5withRSA SHA1withRSA SHA256withRSA SHA384withRSA SHA512withRSA
              * SHA512/224withRSA SHA512/256withRSA
              * SHA3_256withRSA SHA3_384withRSA SHA3_512withRSA
              *  or pre algorithm add /PSS SHA256withRSA/PSS
               */
            explicit RSAPublicKeyVerifier(const std::string& publicKey,
                  const std::string& format = "pem",
                  const std::string& algorithm = "SHA256withRSA");
            ~RSAPublicKeyVerifier() = default;
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
        private:
            std::string publicKey;
            std::string format;
            std::string algorithm;
        private:
            EVP_PKEY* externalEvpKey = nullptr; //外部key，外部自己管理生命周期。
        };



        class EvpKeyGuard {
        public:
            explicit EvpKeyGuard(EVP_PKEY* evpKey, bool needFree) {
                this->evpKey = evpKey;
                this->needFree = needFree;
            }
            ~EvpKeyGuard() {
                if (needFree) {
                    if (evpKey != nullptr) {
                        EVP_PKEY_free(evpKey);
                        evpKey = nullptr;
                    }
                }
            }
        public:
            EvpKeyGuard(EvpKeyGuard const&)            = delete;
            EvpKeyGuard& operator=(EvpKeyGuard const&) = delete;
        private:
            EVP_PKEY* evpKey;
            bool  needFree;
        };

        class EvpKeyCtxGuard {
        public:
            explicit EvpKeyCtxGuard(EVP_PKEY_CTX* ctx) {
                this->ctx = ctx;
            }
            ~EvpKeyCtxGuard() {
                if (ctx != nullptr) {
                    EVP_PKEY_CTX_free(ctx);
                    ctx = nullptr;
                }
            }
        public:
            EvpKeyCtxGuard(EvpKeyCtxGuard const&)            = delete;
            EvpKeyCtxGuard& operator=(EvpKeyCtxGuard const&) = delete;
        private:
            EVP_PKEY_CTX* ctx;
        };



    }
}




#endif //CAMEL_RSA_H
