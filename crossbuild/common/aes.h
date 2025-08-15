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

        class AESEncryptor {
            public:
            explicit AESEncryptor(const std::string& algorithm,
                              const std::string& secret,
                              const std::string& format    = CAMEL_KEY_FORMAT_BASE64);
            ~AESEncryptor() = default;
            public:
                std::string encrypt(const std::string_view& plainText) const;
                std::string encryptToBase64(const std::string_view& plainText) const;
                std::string encryptToHex(const std::string_view& plainText) const;
            private:
                 std::string secretKey;
                 std::string algorithm; //无需传入位数如：128 256，支持传入AES-GCM 即可，长度根据秘钥自动计算。
        };

        class AESDecryptor {
        public:
            /**
             *
             * @param algorithm  AES/GCM/NoPadding、AES/GCM-SIV/NoPadding AES/CCM/NoPadding
             * 其它模式默认PKCS5Padding 如 AES/CBC/PKCS5Padding
             * @param secret
             * @param format
             */
            explicit AESDecryptor(const std::string& algorithm,
                                  const std::string& secret,
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




#endif //AES_H
