//
// Created by baojian on 2025/8/20.
//

#include "test_chacha20.h"
#include "../common/chacha20.h"
#include "../common/file_utils.h"

#include <iostream>

namespace camel {
    namespace crypto {
        void testChaCha20KeyGen() {
            {
                ChaCha20KeyGenerator chacha20Key;
                {
                    std::cout <<"-------------- ChaCha20Key --------------" << std::endl;
                    std::cout << chacha20Key.getHexKey() << std::endl;
                    std::cout << chacha20Key.getBase64Key() << std::endl;
                }
                FileUtils::writeFile("chacha20_key.txt", chacha20Key.getBase64Key(), true);
            }
        }
        void testChaCha20KeyEncrypt() {
            bool passed = true;
            {
                std::string plainText = "hello world chacha20";
                std::string secretKey = " 6C7Otu8XCNCfXuOUJm99xhZOrY+7WZnEDxKWG+HAjPs=";
                ChaCha20Encryptor encryptor(secretKey, "base64");
                ChaCha20Decryptor decryptor(secretKey, "base64");

                std::cout << "------------ ChaCha20 encrypt check1  ------------" << std::endl;
                std::string encryptBase64 =  encryptor.encryptToBase64(plainText);
                std::cout << encryptBase64 << std::endl;
                std::cout << decryptor.decryptFromBase64(encryptBase64) << std::endl;

                passed = passed && plainText == decryptor.decryptFromBase64(encryptBase64);

                std::string java_encrypt_base64 = "AAAAAEZGdZZ4H26h+H1N6KIZLyominEf7JCljIezAJc9lUR0kuSSiD7yTYoJlIr+H+Y0mTxssI7Aae9Vn2w9hL0PxkOdZqI22bGidd5M1Q==";
                std::string javaPlainText = "这是一个使用标准Cipher API的ChaCha20加密解密示例";
                std::cout << decryptor.decryptFromBase64(java_encrypt_base64) << std::endl;

                passed = passed && javaPlainText == decryptor.decryptFromBase64(java_encrypt_base64);

            }

            {
                std::string plainText = "hello world chacha20";
                std::string secretKey = "MepQsv1z55A6TTEaGGrpaAx8stsWH000T9F5UIY7lZQ=";
                ChaCha20Poly1305Encryptor encryptor(secretKey, "base64");
                ChaCha20Poly1305Decryptor decryptor(secretKey, "base64");

                std::cout << "------------ ChaCha20Poly1305 encrypt check1  ------------" << std::endl;
                std::string encryptBase64 =  encryptor.encryptToBase64(plainText);
                std::cout << encryptBase64 << std::endl;
                std::cout << decryptor.decryptFromBase64(encryptBase64) << std::endl;

                passed = passed && plainText == decryptor.decryptFromBase64(encryptBase64);

                { // none aad
                    std::string java_encrypt_base64 = "Cxm7rwkxQ7WzyzPzCFuBkLf4lj+4RkHVexK4oYSe568xx8OowCHF68Fd5dwugzN+ERw=";
                    std::string javaPlainText = "ChaCha20-Poly1305 test";
                    std::cout << decryptor.decryptFromBase64(java_encrypt_base64) << std::endl;
                    passed = passed && javaPlainText == decryptor.decryptFromBase64(java_encrypt_base64);
                }

                { // aad mode test
                    std::string java_encrypt_base64 = "Cxm7rwkxQ7WzyzPzCFuBkLf4lj+4RkHVexK4oYSe568xxzjznKwO4C7DN8/+z0tzu8o=";
                    std::string aad = "user:123;timestamp:20240821";
                    std::string javaPlainText = "ChaCha20-Poly1305 test";
                    std::cout << decryptor.decryptFromBase64WithAAD(java_encrypt_base64, aad) << std::endl;
                    passed = passed && javaPlainText == decryptor.decryptFromBase64WithAAD(java_encrypt_base64, aad);
                }

            }

            if (passed) {
                std::cout << "testChaCha20KeyEncrypt() passed " << std::endl;
            } else {
                std::cout << "testChaCha20KeyEncrypt() failed " << std::endl;
            }

        }
    }
}
