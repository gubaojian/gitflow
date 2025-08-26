//
// Created by baojian on 25-8-14.
//

#ifndef CAMEL_AES_H
#define CAMEL_AES_H
#include "config.h"
#include "hex.h"
#include "base64.h"
#include <string>
#include <openssl/types.h>


namespace camel {
    namespace crypto {
        class AESKeyGenerator {
        public:
            explicit AESKeyGenerator(int keyBitLength=128); //128 192 256
            ~AESKeyGenerator() = default;
        public:
            std::string getKey();
            std::string getHexKey();
            std::string getBase64Key();
        private:
            std::string secretKey;
            int mKeyBitLength = 128;
        };

        //return combine ctrkey and mackey, which is double length of the noraml aes key
        std::string genSivKey(int keyBitLength=128);
        std::string genHexSivKey(int keyBitLength=128);
        std::string genBase64ivKey(int keyBitLength=128);

        std::string getAESKey(const std::string_view& aesKey, const std::string_view& format);
    }
}


namespace camel {
    namespace crypto {
        class AESEncryptor {
        public:
            /**
            * https://developer.android.com/reference/javax/crypto/Cipher
            * @param algorithm  AES/GCM/NoPadding、AES/GCM-SIV/NoPadding AES/CCM/NoPadding
            * 其它模式默认PKCS5Padding 如 AES/CBC/PKCS5Padding
            * @param secret
            * @param format
            */
            explicit AESEncryptor(const std::string& algorithm,
                              const std::string_view& secret,
                              const std::string& format    = "base64");
            ~AESEncryptor() = default;
        public:
            std::string encrypt(const std::string_view& plainText) const;
            std::string encryptToBase64(const std::string_view& plainText) const;
            std::string encryptToHex(const std::string_view& plainText) const;
        public:
            std::string encryptWithAAD(const std::string_view& plainText, const std::string_view& aad) const;
            std::string encryptToBase64WithAAD(const std::string_view& plainText, const std::string_view& aad) const;
            std::string encryptToHexWithAAD(const std::string_view& plainText, const std::string_view& aad) const;
        private:
            std::string secretKey;
            std::string algorithm; //无需传入位数如：128 256，支持传入AES-GCM 即可，长度根据秘钥自动计算。
        };
    }
}


namespace camel {
    namespace crypto {
        class AESDecryptor {
        public:
            /**
             * https://developer.android.com/reference/javax/crypto/Cipher
             * @param algorithm  AES/GCM/NoPadding、AES/GCM-SIV/NoPadding AES/CCM/NoPadding
             * 其它模式默认PKCS5Padding 如 AES/CBC/PKCS5Padding
             * @param secret
             * @param format
             */
            explicit AESDecryptor(const std::string& algorithm,
                                  const std::string_view& secret,
                                  const std::string& format    = CAMEL_KEY_FORMAT_BASE64
            );
            ~AESDecryptor() = default;
        public:
            std::string decrypt(const std::string_view& encryptedData) const;
            std::string decryptFromBase64(const std::string_view& base64EncryptedText) const;
            std::string decryptFromHex(const std::string_view& hexEncryptedText) const;
        public:
            std::string decryptWithAAD(const std::string_view& encryptedData, const std::string_view& aad) const;
            std::string decryptFromBase64WithAAD(const std::string_view& base64EncryptedText, const std::string_view& aad) const;
            std::string decryptFromHexWithAAD(const std::string_view& hexEncryptedText, const std::string_view& aad) const;
        private:
            std::string secretKey;
            std::string algorithm; //无需传入位数如：128 256，支持传入AES-GCM 即可，长度根据秘钥自动计算。
        };
    }
}

namespace camel {
    namespace crypto {
        /**
         *
        * CBC（Cipher Block Chaining）模式：
        * CBC 凭借其相对较好的安全性与平衡的性能，常是许多应用的默认选择。它引入初始化向量（IV），让每个明文块加密前与前一密文块做异或，避免相同明文生成相同密文，适合大块数据加密。
        * 其是 SSL、IPSec 等部分传统安全协议的标准采用模式之一。在像汽车等保守且看重稳定的行业，AES-128 CBC 因安全成熟、硬件支持广泛，也常被优先选用。不过 CBC 易受填充预言攻击，使用时需在错误处理和 IV 管理方面多加留意。
        * GCM（Galois/Counter Mode）模式：
        * GCM 属于 AEAD（认证加密带关联数据）模式，加密同时能验证数据完整性与真实性，可防篡改和重放攻击，契合网络通信、API 加密等需高性能与高安全性的场景。像现代 TLS 1.3 协议加密数据默认就用 AES-GCM。
        * 它基于 CTR 加密机制可并行处理，性能出色，支持添加附加认证数据（AAD）功能，受现代加密实践青睐。只是其实现复杂度比 CBC 高等模式更高一些。
        * ECB（Electronic Codebook）模式：其是最简单模式，但相同明文块会产出相同密文块，易受统计分析攻击，难以隐藏有规律的数据模式，不适合加密图像、视频或长文本等，当下实际使用较少。
G        * CM-SIV 模式：其是 GCM 模式的改进版，具更强的抗 Nonce 重用特性。不过其相对较新，行业生态与标准的支持完善度比不上 GCM，实际应用规模较小。
         *
         */
        // will auto detect use 128 192 256  by aesKey bit length
        // iv is auto generate
        namespace AESCBCUtils {
            std::string encrypt(const std::string_view& aesKey, const std::string_view& data);
            std::string encryptToHex(const std::string_view& aesKey, const std::string_view& data);
            std::string encryptToBase64(const std::string_view& aesKey, const std::string_view& data);
            std::string decrypt(const std::string_view& aesKey, const std::string_view& data);
            std::string decryptFromHex(const std::string_view& aesKey, const std::string_view& data);
            std::string decryptFromBase64(const std::string_view& aesKey, const std::string_view& data);
        }

        // will auto detect use 128 192 256  by aesKey bit length
        // 12 byte nonce and 16 byte tag
        // nonce is auto generate, nonce  + buffer + tag
        namespace AESGCMUtils {
            std::string encrypt(const std::string_view& aesKey, const std::string_view& data);
            std::string encryptToHex(const std::string_view& aesKey, const std::string_view& data);
            std::string encryptToBase64(const std::string_view& aesKey, const std::string_view& data);
            std::string decrypt(const std::string_view& aesKey, const std::string_view& data);
            std::string decryptFromHex(const std::string_view& aesKey, const std::string_view& data);
            std::string decryptFromBase64(const std::string_view& aesKey, const std::string_view& data);

            std::string encryptWithAAD(const std::string_view& aesKey, const std::string_view& data, const std::string_view &aad);
            std::string encryptToHexWithAAD(const std::string_view& aesKey, const std::string_view& data, const std::string_view &aad);
            std::string encryptToBase64WithAAD(const std::string_view& aesKey, const std::string_view& data, const std::string_view &aad);
            std::string decryptWithAAD(const std::string_view& aesKey, const std::string_view& data, const std::string_view &aad);
            std::string decryptFromHexWithAAD(const std::string_view& aesKey, const std::string_view& data, const std::string_view &aad);
            std::string decryptFromBase64WithAAD(const std::string_view& aesKey, const std::string_view& data, const std::string_view &aad);
        }

        /**
         * ECB
         * 无IV，相同明文块加密后结果完全相同，易被统计分析攻击（如暴露数据规律）
         */
        // will auto detect use 128 192 256  by aesKey bit length
        // none need iv
        namespace AESECBUtils {
            std::string encrypt(const std::string_view& aesKey, const std::string_view& data);
            std::string encryptToHex(const std::string_view& aesKey, const std::string_view& data);
            std::string encryptToBase64(const std::string_view& aesKey, const std::string_view& data);
            std::string decrypt(const std::string_view& aesKey, const std::string_view& data);
            std::string decryptFromHex(const std::string_view& aesKey, const std::string_view& data);
            std::string decryptFromBase64(const std::string_view& aesKey, const std::string_view& data);
        }

    }
}




#endif //CAMEL_AES_H
