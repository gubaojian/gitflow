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

        inline void freeRsaEvpKey(EVP_PKEY* key) {
            if (key != nullptr) {
                EVP_PKEY_free(key);
            }
        }


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


         // https://developer.android.com/reference/javax/crypto/Cipher
        //same like java, MGF1 use default sha1
        constexpr auto  RSA_PKCS1Padding = "PKCS1Padding";
        constexpr auto  RSA_OAEPPadding = "OAEPPadding";
        constexpr auto  RSA_OAEPWithSHA_1AndMGF1Padding = " OAEPWithSHA-1AndMGF1Padding";
        constexpr auto  RSA_OAEPwithSHA_256andMGF1Padding = "OAEPwithSHA-256andMGF1Padding";
        constexpr auto  RSA_OAEPwithSHA_384andMGF1Padding = "OAEPwithSHA-384andMGF1Padding";
        constexpr auto  RSA_OAEPwithSHA_512andMGF1Padding = "OAEPwithSHA-512andMGF1Padding";

        //both main and MGF1  use same hash like  sha256
        constexpr auto  RSA_OAEP_SHA256_MGF1_SHA256 = "RSA_OAEP_SHA256_MGF1_SHA256";
        constexpr auto  RSA_OAEP_SHA512_MGF1_SHA512 = "RSA_OAEP_SHA512_MGF1_SHA512";
        constexpr auto  RSA_OAEP_SHA3_256_MGF1_SHA3_256 = "RSA_OAEP_SHA3_256_MGF1_SHA3_256";
        constexpr auto  RSA_OAEP_SHA3_512_MGF1_SHA3_512 = "RSA_OAEP_SHA3_512_MGF1_SHA3_512";

        class RSAPublicKeyEncryptor {
           public:
               /**
                * https://developer.android.com/reference/javax/crypto/Cipher
               * format = "pem", "hex", "base64", "der"
               * OAEPPadding PKCS1Padding default
               * OAEPwithSHA-256andMGF1Padding
               * OAEPwithSHA-384andMGF1Padding
               * OAEPwithSHA-512andMGF1Padding
                */
               explicit RSAPublicKeyEncryptor(const std::string_view& publicKey,
                    const std::string_view& format = "pem",
                    const std::string_view& paddings= RSA_PKCS1Padding);

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
             * https://developer.android.com/reference/javax/crypto/Cipher
              * format = "pem", "hex", "base64", "der"
              * OAEPPadding PKCS1Padding default
              * OAEPwithSHA-256andMGF1Padding
              * OAEPwithSHA-384andMGF1Padding
              * OAEPwithSHA-512andMGF1Padding
               */
            explicit RSAPrivateKeyDecryptor(const std::string_view& privateKey,
                  const std::string_view& format = "pem",
                  const std::string_view& paddings = RSA_PKCS1Padding);
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
              *  or pss mode algorithm like  SHA384withRSA/PSS SHA256withRSA/PSS
               */
            explicit RSAPrivateKeySigner(const std::string_view& publicKey,
                  const std::string_view& format = "pem",
                  const std::string_view& algorithm = "SHA256withRSA");
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
            explicit RSAPublicKeyVerifier(const std::string_view& publicKey,
                  const std::string_view& format = "pem",
                  const std::string_view& algorithm = "SHA256withRSA");
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

        // PKCS1Padding RSA-PKCS#1 v1.5 填充模式
        namespace RSAPKCS1Utils {
            std::string encrypt(const std::string_view& publicKey,  const std::string_view& format, const std::string_view& data);
            std::string encryptToHex(const std::string_view& publicKey,  const std::string_view& format, const std::string_view& data);
            std::string encryptToBase64(const std::string_view& publicKey,  const std::string_view& format, const std::string_view& data);

            std::string decrypt(const std::string_view& privateKey,const std::string_view& format,  const std::string_view& data);
            std::string decryptFromHex(const std::string_view& privateKey,const std::string_view& format,  const std::string_view& data);
            std::string decryptFromBase64(const std::string_view& privateKey,const std::string_view& format,  const std::string_view& data);

            // 复用EVP_PKEY，减少key解析创建开销, 复用key，速度快一些
            std::string encryptByEVPKey(EVP_PKEY* publicKey, const std::string_view& data);
            std::string encryptByEVPKeyToHex(EVP_PKEY* publicKey, const std::string_view& data);
            std::string encryptByEVPKeyToBase64(EVP_PKEY* publicKey, const std::string_view& data);

            std::string decryptByEvpKey(EVP_PKEY* privateKey,  const std::string_view& data);
            std::string decryptByEvpKeyFromHex(EVP_PKEY* privateKey,  const std::string_view& data);
            std::string decryptByEvpKeyFromBase64(EVP_PKEY* privateKey,  const std::string_view& data);
        }


        // 和 java的 RSA_OAEPwithSHA_256andMGF1Padding 模式相同
        // RSA-OAEP padding模式 模式，主哈希用 SHA2-256， MGF1 用默认sha1
        namespace RSAOAEPSha256MGF1Sha1Utils {
            std::string encrypt(const std::string_view& publicKey,  const std::string_view& format, const std::string_view& data);
            std::string encryptToHex(const std::string_view& publicKey,  const std::string_view& format, const std::string_view& data);
            std::string encryptToBase64(const std::string_view& publicKey,  const std::string_view& format, const std::string_view& data);

            std::string decrypt(const std::string_view& privateKey,const std::string_view& format,  const std::string_view& data);
            std::string decryptFromHex(const std::string_view& privateKey,const std::string_view& format,  const std::string_view& data);
            std::string decryptFromBase64(const std::string_view& privateKey,const std::string_view& format,  const std::string_view& data);

            // 复用EVP_PKEY，减少key解析创建开销, 复用key，速度快一些
            std::string encryptByEVPKey(EVP_PKEY* publicKey, const std::string_view& data);
            std::string encryptByEVPKeyToHex(EVP_PKEY* publicKey, const std::string_view& data);
            std::string encryptByEVPKeyToBase64(EVP_PKEY* publicKey, const std::string_view& data);

            std::string decryptByEvpKey(EVP_PKEY* privateKey,  const std::string_view& data);
            std::string decryptByEvpKeyFromHex(EVP_PKEY* privateKey,  const std::string_view& data);
            std::string decryptByEvpKeyFromBase64(EVP_PKEY* privateKey,  const std::string_view& data);
        }

        /**
         * JAVA通过设置 OAEPParameterSpec来设置MGF1的hash算法
        * OAEPParameterSpec oaepSpec = new OAEPParameterSpec(
        *     "SHA-256",          // 主哈希函数
        *     "MGF1",             // 掩码生成函数
        *     new MGF1ParameterSpec("SHA-256"),  // MGF1 使用 SHA-256
        *     PSource.PSpecified.DEFAULT
        * );

         */
        // RSA-OAEP 模式，主哈希和 MGF1 哈希均使用 SHA-256
        namespace RSAOAEPSha256MGF1Sha256Utils {
            std::string encrypt(const std::string_view& publicKey,  const std::string_view& format, const std::string_view& data);
            std::string encryptToHex(const std::string_view& publicKey,  const std::string_view& format, const std::string_view& data);
            std::string encryptToBase64(const std::string_view& publicKey,  const std::string_view& format, const std::string_view& data);

            std::string decrypt(const std::string_view& privateKey,const std::string_view& format,  const std::string_view& data);
            std::string decryptFromHex(const std::string_view& privateKey,const std::string_view& format,  const std::string_view& data);
            std::string decryptFromBase64(const std::string_view& privateKey,const std::string_view& format,  const std::string_view& data);

            // 复用EVP_PKEY，减少key解析创建开销, 复用key，速度快一些
            std::string encryptByEVPKey(EVP_PKEY* publicKey, const std::string_view& data);
            std::string encryptByEVPKeyToHex(EVP_PKEY* publicKey, const std::string_view& data);
            std::string encryptByEVPKeyToBase64(EVP_PKEY* publicKey, const std::string_view& data);

            std::string decryptByEvpKey(EVP_PKEY* privateKey,  const std::string_view& data);
            std::string decryptByEvpKeyFromHex(EVP_PKEY* privateKey,  const std::string_view& data);
            std::string decryptByEvpKeyFromBase64(EVP_PKEY* privateKey,  const std::string_view& data);
        }


        /**
         * 默认 PKCS1 填充， Java默认签名填充方式
         */
        namespace RSAPKCS1Sha256SignUtils {
            std::string sign(const std::string_view& privateKey,const std::string_view& format,  const std::string_view& data);
            std::string signToHex(const std::string_view& privateKey,const std::string_view& format,  const std::string_view& data);
            std::string signToBase64(const std::string_view& privateKey,const std::string_view& format,  const std::string_view& data);

            bool verify(const std::string_view& publicKey,  const std::string_view& format, const std::string_view& data, const std::string_view& sign);
            bool verifyHexSign(const std::string_view& publicKey,  const std::string_view& format, const std::string_view& data, const std::string_view& sign);
            bool verifyBase64Sign(const std::string_view& publicKey,  const std::string_view& format, const std::string_view& data, const std::string_view& sign);

            // 复用EVP_PKEY，减少key解析创建开销, 复用key，速度快一些
            std::string signByEVPKey(EVP_PKEY* privateKey, const std::string_view& data);
            std::string signByEVPKeyToHex(EVP_PKEY* privateKey, const std::string_view& data);
            std::string signByEVPKeyToBase64(EVP_PKEY* privateKey, const std::string_view& data);

            bool verifyByEVPKey(EVP_PKEY* publicKey,  const std::string_view& data, const std::string_view& sign);
            bool verifyHexSignByEVPKey(EVP_PKEY* publicKey,  const std::string_view& data, const std::string_view& sign);
            bool verifyBase64SignByEVPKey(EVP_PKEY* publicKey,  const std::string_view& data, const std::string_view& sign);
        }

        /**
         * 默认 PSS 填充
         */
        namespace RSAPSSSha256SignUtils {
            std::string sign(const std::string_view& privateKey,const std::string_view& format,  const std::string_view& data);
            std::string signToHex(const std::string_view& privateKey,const std::string_view& format,  const std::string_view& data);
            std::string signToBase64(const std::string_view& privateKey,const std::string_view& format,  const std::string_view& data);

            bool verify(const std::string_view& publicKey,  const std::string_view& format, const std::string_view& data, const std::string_view& sign);
            bool verifyHexSign(const std::string_view& publicKey,  const std::string_view& format, const std::string_view& data, const std::string_view& sign);
            bool verifyBase64Sign(const std::string_view& publicKey,  const std::string_view& format, const std::string_view& data, const std::string_view& sign);


            // 复用EVP_PKEY，减少key解析创建开销, 复用key，速度快一些
            std::string signByEVPKey(EVP_PKEY* privateKey, const std::string_view& data);
            std::string signByEVPKeyToHex(EVP_PKEY* privateKey, const std::string_view& data);
            std::string signByEVPKeyToBase64(EVP_PKEY* privateKey, const std::string_view& data);

            bool verifyByEVPKey(EVP_PKEY* publicKey,  const std::string_view& data, const std::string_view& sign);
            bool verifyHexSignByEVPKey(EVP_PKEY* publicKey,  const std::string_view& data, const std::string_view& sign);
            bool verifyBase64SignByEVPKey(EVP_PKEY* publicKey,  const std::string_view& data, const std::string_view& sign);

        }



    }
}




#endif //CAMEL_RSA_H
