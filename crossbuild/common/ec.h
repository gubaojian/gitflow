//
// Created by baojian on 2025/8/18.
//

#ifndef CAMEL_ELLIPTIC_CURVE_H
#define CAMEL_ELLIPTIC_CURVE_H
#include <iostream>
#include <string>
#include <string_view>
#include <openssl/types.h>

#include "config.h"
#include "openssl/evp.h"

namespace camel {
    namespace crypto {

        EVP_PKEY* ECPublicKeyFromPem(const std::string_view& pemKey);
        EVP_PKEY* ECPublicKeyFromBase64(const std::string_view& base64Key);
        EVP_PKEY* ECPublicKeyFromHex(const std::string_view& hexKey);
        EVP_PKEY* ECPublicKeyFromDer(const std::string_view& derKey);
        EVP_PKEY* ECPublicKeyFromDerByBio(const std::string_view& derKey);
        EVP_PKEY* ECPublicKeyFrom(const std::string_view& publicKey, const std::string_view& format);

        EVP_PKEY* ECPrivateKeyFromPem(const std::string_view& pemKey);
        EVP_PKEY* ECPrivateKeyFromBase64(const std::string_view& base64Key);
        EVP_PKEY* ECPrivateKeyFromHex(const std::string_view& hexKey);
        EVP_PKEY* ECPrivateKeyFromDer(const std::string_view& derKey);
        EVP_PKEY* ECPrivateKeyFromDerByBio(const std::string_view& derKey);
        EVP_PKEY* ECPrivateKeyFrom(const std::string_view& privateKey, const std::string_view& format);

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
            *  x25519/x448：专门用于 ECDH 密钥交换（基于 Montgomery 曲线优化）。
            *  ed25519/ed448：专门用于 数字签名（基于 Edwards 曲线优化）。
            *  Edwards 曲线（ed25519、ed448）：
            *  对应的算法是 EdDSA（Edwards-curve Digital Signature Algorithm），而非 ECDSA。
            *  特点：签名速度极快、抗侧信道攻击能力强，广泛用于 SSH 密钥、容器镜像签名（如 Docker）、加密货币（如 Monero）。
            *  与 ECDSA 的区别：EdDSA 是专门为 Edwards 曲线设计的签名算法，流程更简洁，而 ECDSA 是通用椭圆曲线签名框架。
            *  Montgomery 曲线（x25519、x448）：
            *  对应的算法是 ECDH（椭圆曲线 Diffie-Hellman） 的优化版本，仅用于 密钥交换（生成共享密钥），不用于签名。
            *  应用：TLS 1.3 的密钥协商、Signal 等即时通讯工具的端到端加密。
            *  国密曲线：SM2 请使用 SM2KeyPairGenerator
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





namespace camel {
    namespace crypto {

        class ECDHSharedSecretGenerator {
            public:
                explicit ECDHSharedSecretGenerator(const std::string_view& localPrivateKey, const std::string_view& remotePublicKey,
                    const std::string_view& format);
            ~ECDHSharedSecretGenerator() = default;
            public:
                std::string getGenSecret();
                std::string getGenSecretHex();
                std::string getGenSecretBase64();
            private:
                 std::string genSecret;
        };

    }
}

namespace camel {
    namespace crypto {
        class HKDFSecretGenerator {
        public:
            explicit HKDFSecretGenerator(const std::string_view& secret,
                const std::string_view& infoKey,
                const std::string_view& salt, const std::string_view& hashName = "SHA2-256",
                size_t secretLen = 0);//0 根据hash自动计算长度
            ~HKDFSecretGenerator() = default;
        public:
            std::string getGenSecret();
            std::string getGenSecretHex();
            std::string getGenSecretBase64();
        private:
            std::string genSecret;
        };
    }
}




namespace camel {
    namespace crypto {
        class ECDSAPrivateKeySigner {
            public:
                /**
                  *  支持的曲线： NIST 曲线：secp256r1（P-256）、secp384r1（P-384）、secp521r1（P-521）
                  *   区块链常用：secp256k1
                  * format = "pem", "hex", "base64", "der"
                  * algorithm SHA1withECDSA HA224withECDSA SHA256withECDSA SHA384withECDSA  SHA512withECDSA
                  * SHA512/224withECDSA  SHA512/256withECDSA
                  * SHA3_256withECDSA  SHA3_384withECDSA  SHA3_512withECDSA
                   */
                explicit ECDSAPrivateKeySigner(const std::string_view& privateKey,
                      const std::string_view& format = "pem",
                      const std::string_view& algorithm = "SHA256withECDSA");
                ~ECDSAPrivateKeySigner() = default;
            public:
                ECDSAPrivateKeySigner(const ECDSAPrivateKeySigner&) = delete;
                ECDSAPrivateKeySigner& operator=(const ECDSAPrivateKeySigner&) = delete;
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
    }
}


namespace camel {
    namespace crypto {
        class ECDSAPublicKeyVerifier {
        public:
            /**
              *  支持的曲线： NIST 曲线：secp256r1（P-256）、secp384r1（P-384）、secp521r1（P-521）
              *  区块链常用：secp256k1
              * format = "pem", "hex", "base64", "der"
              * algorithm
              * MD5withRSA SHA1withRSA SHA256withRSA SHA384withRSA SHA512withRSA
              * SHA512/224withRSA SHA512/256withRSA
              * SHA3_256withRSA SHA3_384withRSA SHA3_512withRSA
              *  or pre algorithm add /PSS SHA256withRSA/PSS
               */
            explicit ECDSAPublicKeyVerifier(const std::string_view& publicKey,
                  const std::string_view& format = "pem",
                  const std::string_view& algorithm = "SHA256withRSA");
            ~ECDSAPublicKeyVerifier() = default;
        public:
            ECDSAPublicKeyVerifier(const ECDSAPublicKeyVerifier&) = delete;
            ECDSAPublicKeyVerifier& operator=(const ECDSAPublicKeyVerifier&) = delete;
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

    }
}


namespace camel {
    namespace crypto {
        class EDDSAPrivateKeySigner {
            public:
              /**
               *  支持的曲线： ED25519、ED448
               * format = "pem", "hex", "base64", "der"
                */
                explicit EDDSAPrivateKeySigner(const std::string_view& privateKey,
                      const std::string_view& format = "pem");
                ~EDDSAPrivateKeySigner() = default;
            public:
                EDDSAPrivateKeySigner(const EDDSAPrivateKeySigner&) = delete;
                EDDSAPrivateKeySigner& operator=(const EDDSAPrivateKeySigner&) = delete;
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
            private:
                EVP_PKEY* externalEvpKey = nullptr; //外部key，外部自己管理生命周期。
        };
    }
}


namespace camel {
    namespace crypto {
        class EDDSAPublicKeyVerifier {
        public:
            /**
              *  支持的曲线： ED25519、ED448
              * format = "pem", "hex", "base64", "der"
               */
            explicit EDDSAPublicKeyVerifier(const std::string_view& publicKey,
                  const std::string_view& format = "pem");
            ~EDDSAPublicKeyVerifier() = default;
        public:
            EDDSAPublicKeyVerifier(const EDDSAPublicKeyVerifier&) = delete;
            EDDSAPublicKeyVerifier& operator=(const EDDSAPublicKeyVerifier&) = delete;
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
        private:
            EVP_PKEY* externalEvpKey = nullptr; //外部key，外部自己管理生命周期。
        };

    }
}





#endif //CAMEL_ELLIPTIC_CURVE_H