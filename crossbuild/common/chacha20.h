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
        std::string getChaCha20Poly1305Key(const std::string_view& chaCha20Key, const std::string_view& format);
    }
}

namespace camel {
    namespace crypto {
         /**
           * The ChaCha20 stream cipher. The key length is 256 bits, the IV is 128 bits long.
           * The first 64 bits consists of a counter in little-endian order followed by a 64 bit nonce.
           * 标准12位 nonce iv，openssl中的实现是16位， https://docs.openssl.org/3.1/man3/EVP_chacha20/
           * https://github.com/openssl/openssl/issues/21095
           * java通过类似下面代码把12位iv扩展为16未，前4字节设置为0：
           * byte[] opensslCompat = new byte[4]; //openssl中的charchar20 是16位iv
           * byte[] ciphertext = encrypt(originalText.getBytes(StandardCharsets.UTF_8), restoredKey, nonce);
           * org.bouncycastle.util.Arrays.concatenate(opensslCompat, nonce, ciphertext)
           */
        class ChaCha20Encryptor {
        public:
            /**
             * ChaCha20-Poly1305 支持AAD ChaCha20不支持AAD
            * https://developer.android.com/reference/javax/crypto/Cipher
            * @param secret 32 byte
            * @param format hex base64 raw
            */
            explicit ChaCha20Encryptor(const std::string_view& secret,
                              const std::string_view& format = "base64");
            ~ChaCha20Encryptor() = default;
        public:
            // 4byte[0] + 12 byte[nonce] + [密文]
            std::string encrypt(const std::string_view& plainText) const;
            std::string encryptToBase64(const std::string_view& plainText) const;
            std::string encryptToHex(const std::string_view& plainText) const;
        private:
            std::string secretKey;
        };
    }
}

namespace camel {
    namespace crypto {
        class ChaCha20Decryptor {
        public:
            /**
             * https://developer.android.com/reference/javax/crypto/Cipher
             * @param secret 32 byte
             * @param format
             */
            explicit ChaCha20Decryptor( const std::string_view& secret,
                                  const std::string_view& format    = "base64"
            );
            ~ChaCha20Decryptor() = default;
        public:
            std::string decrypt(const std::string_view& encryptedData) const;
            std::string decryptFromBase64(const std::string_view& base64EncryptedText) const;
            std::string decryptFromHex(const std::string_view& hexEncryptedText) const;
        private:
            std::string secretKey;
        };
    }
}


namespace camel {
    namespace crypto {
        /**
         * https://docs.openssl.org/3.1/man3/EVP_chacha20/#description
         */
        class ChaCha20Poly1305Encryptor {
        public:
            /**
             * ChaCha20-Poly1305 支持AAD ChaCha20不支持AAD
            * https://developer.android.com/reference/javax/crypto/Cipher
            * @param secret 32 byte
            * @param format hex base64 raw
            */
            explicit ChaCha20Poly1305Encryptor(const std::string_view& secret,
                              const std::string_view& format = "base64");
            ~ChaCha20Poly1305Encryptor() = default;
        public:
            // 4byte[0] + 12 byte[nonce] + [密文] + 16 byte[tag]
            std::string encrypt(const std::string_view& plainText) const;
            std::string encryptToBase64(const std::string_view& plainText) const;
            std::string encryptToHex(const std::string_view& plainText) const;
        public:
            std::string encryptWithAAD(const std::string_view& plainText, const std::string_view& aad) const;
            std::string encryptToBase64WithAAD(const std::string_view& plainText, const std::string_view& aad) const;
            std::string encryptToHexWithAAD(const std::string_view& plainText, const std::string_view& aad) const;
        private:
            std::string secretKey;
        };
    }
}

namespace camel {
    namespace crypto {
        class ChaCha20Poly1305Decryptor {
        public:
            /**
             * https://developer.android.com/reference/javax/crypto/Cipher
             * ChaCha20-Poly1305 支持AAD
             * @param secret 32 byte
             * @param format
             */
            explicit ChaCha20Poly1305Decryptor( const std::string_view& secret,
                                  const std::string_view& format    = "base64"
            );
            ~ChaCha20Poly1305Decryptor() = default;
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
        };
    }
}

#endif //CAMEL_CHACHA20_H