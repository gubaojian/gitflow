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
            RSAPublicKeyEncryptor encryptorPem(rsa.getPemPublicKey());
            RSAPrivateKeyDecryptor decryptorPem(rsa.getPemPrivateKey());
            RSAPublicKeyEncryptor encryptorDer(rsa.getPublicKey(), "der");
            RSAPrivateKeyDecryptor decryptorDer(rsa.getPrivateKey(), "der");
            RSAPublicKeyEncryptor encryptorHex(rsa.getHexPublicKey(), "hex");
            RSAPrivateKeyDecryptor decryptorHex(rsa.getHexPrivateKey(), "hex");
            RSAPublicKeyEncryptor encryptorBase64(rsa.getBase64NewLinePublicKey(), "base64");
            RSAPrivateKeyDecryptor decryptorBase64(rsa.getBase64NewLinePrivateKey(), "base64");
            {
                std::string plainText = "hello world";
                std::cout <<"short text demo " << std::endl;
                std::string encryptedTextPem = encryptorPem.encrypt(plainText);
                std::string encryptedTextDer = encryptorDer.encrypt(plainText);
                std::string encryptedTextHex = encryptorHex.encrypt(plainText);
                std::string encryptedTextBase64 = encryptorBase64.encrypt(plainText);
                std::cout << encryptorPem.encryptToHex(plainText) << std::endl;
                std::cout << encryptorPem.encryptToBase64(plainText) << std::endl;
                std::cout << "pem result test result" << std::endl;
                std::cout << decryptorPem.decrypt(encryptedTextPem) << std::endl;
                std::cout << decryptorDer.decrypt(encryptedTextPem) << std::endl;
                std::cout << decryptorHex.decrypt(encryptedTextPem) << std::endl;
                std::cout << decryptorBase64.decrypt(encryptedTextPem) << std::endl;

                std::cout << "der result test result" << std::endl;
                std::cout << decryptorPem.decrypt(encryptedTextDer) << std::endl;
                std::cout << decryptorDer.decrypt(encryptedTextDer) << std::endl;
                std::cout << decryptorHex.decrypt(encryptedTextDer) << std::endl;
                std::cout << decryptorBase64.decrypt(encryptedTextDer) << std::endl;
            }

            {
                std::string longPlainText = "hello world";
                for (int i=0; i<1024; i++) {
                    longPlainText.append(std::to_string(i));
                    longPlainText.append("_");
                }
                std::cout <<"long text demo " << std::endl;
                std::string encryptedText = encryptorPem.encrypt(longPlainText);
                std::cout << encryptorPem.encryptToHex(longPlainText) << std::endl;
                std::cout << encryptorPem.encryptToBase64(longPlainText) << std::endl;
                std::cout << decryptorPem.decrypt(encryptedText) << std::endl;

            }

        }

        void demoRsaCryptPerf() {
            RSAKeyPairGenerator rsa;
            std::string publicKey = rsa.getPemPublicKey();
            RSAPublicKeyEncryptor encryptor(rsa.getPemPublicKey());
            RSAPrivateKeyDecryptor decryptor(rsa.getPemPrivateKey());
            int test_count = 5000;
            {
                auto start = std::chrono::high_resolution_clock::now();
                auto end = std::chrono::high_resolution_clock::now();
                auto used = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

                start = std::chrono::high_resolution_clock::now();
                std::string plainText = "hello world";
                for(int i=0; i<test_count; i++) {
                    std::string encryptedText = encryptor.encrypt(plainText);
                }
                end = std::chrono::high_resolution_clock::now();
                used = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
                std::cout << "rsa encrypt times per second " << ( (double)test_count)/(used.count()/1000.0f) << std::endl;
            }

            {
                auto start = std::chrono::high_resolution_clock::now();
                auto end = std::chrono::high_resolution_clock::now();
                auto used = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

                start = std::chrono::high_resolution_clock::now();
                std::string plainText = "hello world";

                for(int i=0; i<test_count; i++) {
                    std::string encryptedText = encryptor.encryptToHex(plainText);
                }
                end = std::chrono::high_resolution_clock::now();
                used = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
                std::cout << "rsa encrypt hex times per second " << ( (double)test_count)/(used.count()/1000.0f) << std::endl;

            }

            {
                auto start = std::chrono::high_resolution_clock::now();
                auto end = std::chrono::high_resolution_clock::now();
                auto used = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

                start = std::chrono::high_resolution_clock::now();
                std::string plainText = "hello world";
                for(int i=0; i<test_count; i++) {
                    std::string encryptedText = encryptor.encryptToBase64(plainText);
                }
                end = std::chrono::high_resolution_clock::now();
                used = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
                std::cout << "rsa encrypt base64 times per second " << ( (double)test_count)/(used.count()/1000.0f) << std::endl;

            }
        }

        void demoRsaDecryptPerf() {
            RSAKeyPairGenerator rsa;
            std::string publicKey = rsa.getPemPublicKey();
            RSAPublicKeyEncryptor encryptor(rsa.getPemPublicKey());
            RSAPrivateKeyDecryptor decryptor(rsa.getPemPrivateKey());
            int test_count = 5000;
            {
                auto start = std::chrono::high_resolution_clock::now();
                auto end = std::chrono::high_resolution_clock::now();
                auto used = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

                start = std::chrono::high_resolution_clock::now();
                std::string plainText = "hello world";
                std::string encryptedText = encryptor.encrypt(plainText);
                for(int i=0; i<test_count; i++) {
                    decryptor.decrypt(encryptedText);
                }
                end = std::chrono::high_resolution_clock::now();
                used = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
                std::cout << "rsa decrypt times per second " << ( (double)test_count)/(used.count()/1000.0f) << std::endl;
            }

            {
                auto start = std::chrono::high_resolution_clock::now();
                auto end = std::chrono::high_resolution_clock::now();
                auto used = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

                start = std::chrono::high_resolution_clock::now();
                std::string plainText = "hello world";
                std::string encryptedText = encryptor.encryptToHex(plainText);

                for(int i=0; i<test_count; i++) {
                    decryptor.decryptFromHex(encryptedText);
                }
                end = std::chrono::high_resolution_clock::now();
                used = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
                std::cout << "rsa decrypt hex times per second " << ( (double)test_count)/(used.count()/1000.0f) << std::endl;

            }

            {
                auto start = std::chrono::high_resolution_clock::now();
                auto end = std::chrono::high_resolution_clock::now();
                auto used = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

                start = std::chrono::high_resolution_clock::now();
                std::string plainText = "hello world";
                std::string encryptedText = encryptor.encryptToBase64(plainText);
                int test_count = 5000;
                for(int i=0; i<test_count; i++) {
                    decryptor.decryptFromBase64(encryptedText);
                }
                end = std::chrono::high_resolution_clock::now();
                used = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
                std::cout << "rsa decrypt base64 times per second " << ( (double)test_count)/(used.count()/1000.0f) << std::endl;

            }
        }



    }
}
