//
// Created by baojian on 2025/8/20.
//

#ifndef CAMEL_CHACHA20_H
#define CAMEL_CHACHA20_H
#include <string>

#include "config.h"

namespace camel {
    namespace crypto {
        class ChaCha20KeyGenerator {
        public:
            explicit ChaCha20KeyGenerator(); // chacha20 is always 256
            ~ChaCha20KeyGenerator() = default;
        public:
            std::string getKey();
            std::string getHexKey();
            std::string getBase64Key();
        private:
            std::string secretKey;
        };
    }
}



namespace camel {
    namespace crypto {
        std::string getChaCha20Key(const std::string_view& chaCha20Key, const std::string_view& format);
    }
}

namespace camel {
    namespace crypto {
        class ChaCha20Encryptor {
        public:
            /**
             * ChaCha20-Poly1305 支持AAD ChaCha20不支持AAD
            * https://developer.android.com/reference/javax/crypto/Cipher
            * @param secret
            * @param format hex base64 raw
            */
            explicit ChaCha20Encryptor(const std::string_view& algorithm, const std::string_view& secret,
                              const std::string_view& format    = "base64");
            ~ChaCha20Encryptor() = default;
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
            std::string algorithm;
        };
    }
}

namespace camel {
    namespace crypto {
        class ChaCha20Decryptor {
        public:
            /**
             * https://developer.android.com/reference/javax/crypto/Cipher
             * ChaCha20-Poly1305 支持AAD ChaCha20不支持AAD
             * @param algorithm  ChaCha20  ChaCha20-Poly1305
             * @param secret
             * @param format
             */
            explicit ChaCha20Decryptor(const std::string_view& algorithm,
                                  const std::string_view& secret,
                                  const std::string_view& format    = CAMEL_KEY_FORMAT_BASE64
            );
            ~ChaCha20Decryptor() = default;
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

#endif //CAMEL_CHACHA20_H