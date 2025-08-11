//
// Created by baojian on 25-8-5.
//

#include "demo_rsa.h"

#include <iostream>
#include <sstream>

#include "../common/file_utils.h"

using namespace camel::crypto;

namespace camel {
    namespace crypto {
        void demoRsaGenerateKey() {
            {
                RSAKeyPairGenerator rsa;
                {
                    rsa.getPemPrivateKey();
                    rsa.getPemPublicKey();
                }
                FileUtils::writeFile("demo_private_key.pem", rsa.getPemPrivateKey(), true);
                FileUtils::writeFile("demo_public_key.pem", rsa.getPemPublicKey(), true);
            }

        }

        void demoRsaEncrypt() {
            RSAKeyPairGenerator rsa;
            std::string publicKey = rsa.getPemPublicKey();
            RSAPublicKeyEncryptor encryptor(rsa.getPemPublicKey());
            RSAPrivateKeyDecryptor decryptor(rsa.getPemPrivateKey());
            {
                std::string plainText = "hello world";
                std::cout <<"short text demo " << std::endl;
                std::string encryptedText = encryptor.encrypt(plainText);
                std::cout << encryptor.encryptToHex(plainText) << std::endl;
                std::cout << encryptor.encryptToBase64(plainText) << std::endl;
                std::cout << decryptor.decrypt(encryptedText) << std::endl;
            }

            {
                std::string longPlainText = "hello world";
                for (int i=0; i<1024; i++) {
                    longPlainText.append(std::to_string(i));
                    longPlainText.append("_");
                }
                std::cout <<"long text demo " << std::endl;
                std::string encryptedText = encryptor.encrypt(longPlainText);
                std::cout << encryptor.encryptToHex(longPlainText) << std::endl;
                std::cout << encryptor.encryptToBase64(longPlainText) << std::endl;
                std::cout << decryptor.decrypt(encryptedText) << std::endl;

            }

        }

        void demoRsaPerf() {
            RSAKeyPairGenerator rsa;
            std::string publicKey = rsa.getPemPublicKey();
            RSAPublicKeyEncryptor encryptor(rsa.getPemPublicKey());
            RSAPrivateKeyDecryptor decryptor(rsa.getPemPrivateKey());
            {
                auto start = std::chrono::high_resolution_clock::now();
                auto end = std::chrono::high_resolution_clock::now();
                auto used = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

                start = std::chrono::high_resolution_clock::now();
                std::string plainText = "hello world";
                std::cout <<"short text demo " << std::endl;
                std::string encryptedText = encryptor.encrypt(plainText);
                int test_count = 10000;
                for(int i=0; i<test_count; i++) {
                    decryptor.decrypt(encryptedText);
                }
                end = std::chrono::high_resolution_clock::now();
                used = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
                std::cout << "rsa decrypt used " << used.count() << "ms times " <<  test_count << std::endl;
            }
        }



    }
}
