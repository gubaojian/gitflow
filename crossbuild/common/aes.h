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
            std::string geKey();
            std::string getHexKey();
            std::string getBase64Key();
        private:
            std::string secretKey;
            int mKeyBitLength = 128;
        };

        class AESEncryptor {
            public:
                explicit AESEncryptor(const std::string& secret, const std::string& format = CAMEL_KEY_FORMAT_BASE64);
            ~AESEncryptor() = default;
            public:
                std::string encrypt(const std::string_view& plainText) const;
                std::string encryptToBase64(const std::string_view& plainText) const;
                std::string encryptToHex(const std::string_view& plainText) const;
            private:
               std::string secretKey;
        };

        class AESDecryptor {
        public:
            explicit AESDecryptor(const std::string& algorithm,
                const std::string& secret,
                const std::string& format    = CAMEL_KEY_FORMAT_BASE64
                );
            ~AESDecryptor() = default;
        public:
            std::string decrypt(const std::string_view& encryptedData) const;
            std::string decryptFromBase64(const std::string_view& base64EncryptedText) const;
            std::string decryptFromHex(const std::string_view& hexEncryptedText) const;
        private:
            std::string secretKey;
            std::string algorithm;
        };
    }
}




#endif //AES_H
