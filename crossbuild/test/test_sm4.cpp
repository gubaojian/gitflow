//
// Created by baojian on 2025/8/25.
//

#include "test_sm4.h"
#include "../common/sm4.h"
#include <iostream>


namespace camel {
    namespace crypto {
        void testSM4KeyGen() {
            bool passed = true;
            {
                SM4KeyGenerator generator;
                passed = passed && (generator.getKey().size() > 0);
                std::cout << "----------------------- SM4KeyGen -----------------------" << std::endl;
                std::cout << generator.getHexKey() << std::endl;
                std::cout << generator.getBase64Key() << std::endl;
            }
            if (passed) {
                std::cout << "testSM4KeyGen() passed " << std::endl;
            } else {
                std::cout << "testSM4KeyGen() failed " << std::endl;
            }
        }
        void testSM4KeyEncrypt() {
            bool passed = true;
            {
                std::string plainText = "hello world sm4";
                std::string secretKey = "iC3eHDlJvHvVgiO2Nl43/Q==";
                std::cout << "----------------------- SM4/ECB/PKCS5Padding -----------------------" << std::endl;
                SM4Encryptor encryptor("SM4/ECB/PKCS5Padding", secretKey, "base64");
                SM4Decryptor decryptor("SM4/ECB/PKCS5Padding", secretKey, "base64");
                std::cout << encryptor.encryptToBase64(plainText) << std::endl;
                std::cout << decryptor.decryptFromBase64(encryptor.encryptToBase64(plainText)) << std::endl;

                passed = passed && (decryptor.decryptFromBase64(encryptor.encryptToBase64(plainText)) == plainText);
            }


            {
                std::string plainText = "hello world sm4";
                std::string secretKey = "iC3eHDlJvHvVgiO2Nl43/Q==";
                std::cout << "----------------------- SM4/CBC/PKCS5Padding -----------------------" << std::endl;
                SM4Encryptor encryptor("SM4/CBC/PKCS5Padding", secretKey, "base64");
                SM4Decryptor decryptor("SM4/CBC/PKCS5Padding", secretKey, "base64");
                std::cout << encryptor.encryptToBase64(plainText) << std::endl;
                std::cout << decryptor.decryptFromBase64(encryptor.encryptToBase64(plainText)) << std::endl;

                passed = passed && (decryptor.decryptFromBase64(encryptor.encryptToBase64(plainText)) == plainText);
            }


            {
                std::string plainText = "hello world sm4";
                std::string secretKey = "iC3eHDlJvHvVgiO2Nl43/Q==";
                std::cout << "----------------------- SM4/CFB/PKCS5Padding -----------------------" << std::endl;
                SM4Encryptor encryptor("SM4/CFB/PKCS5Padding", secretKey, "base64");
                SM4Decryptor decryptor("SM4/CFB/PKCS5Padding", secretKey, "base64");
                std::cout << encryptor.encryptToBase64(plainText) << std::endl;
                std::cout << decryptor.decryptFromBase64(encryptor.encryptToBase64(plainText)) << std::endl;

                passed = passed && (decryptor.decryptFromBase64(encryptor.encryptToBase64(plainText)) == plainText);
            }

            {
                std::string plainText = "hello world sm4";
                std::string secretKey = "iC3eHDlJvHvVgiO2Nl43/Q==";
                std::cout << "----------------------- SM4/OFB/PKCS5Padding -----------------------" << std::endl;
                SM4Encryptor encryptor("SM4/OFB/PKCS5Padding", secretKey, "base64");
                SM4Decryptor decryptor("SM4/OFB/PKCS5Padding", secretKey, "base64");
                std::cout << encryptor.encryptToBase64(plainText) << std::endl;
                std::cout << decryptor.decryptFromBase64(encryptor.encryptToBase64(plainText)) << std::endl;

                passed = passed && (decryptor.decryptFromBase64(encryptor.encryptToBase64(plainText)) == plainText);
            }

            {
                std::string plainText = "hello world sm4";
                std::string secretKey = "iC3eHDlJvHvVgiO2Nl43/Q==";
                std::cout << "----------------------- SM4/CTR/PKCS5Padding -----------------------" << std::endl;
                SM4Encryptor encryptor("SM4/CTR/PKCS5Padding", secretKey, "base64");
                SM4Decryptor decryptor("SM4/CTR/PKCS5Padding", secretKey, "base64");
                std::cout << encryptor.encryptToBase64(plainText) << std::endl;
                std::cout << decryptor.decryptFromBase64(encryptor.encryptToBase64(plainText)) << std::endl;

                passed = passed && (decryptor.decryptFromBase64(encryptor.encryptToBase64(plainText)) == plainText);
            }




            if (passed) {
                std::cout << "testSM4KeyEncrypt() passed " << std::endl;
            } else {
                std::cout << "testSM4KeyEncrypt() failed " << std::endl;
            }
        }
    }
}
