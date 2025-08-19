//
// Created by efurture on 25-8-19.
//

#include "test_sm2.h"

#include <iomanip>

#include "../common/sm2.h"
#include <iostream>


namespace camel {
    namespace crypto {
        void testSM2KeyGen() {
            bool passed = true;
            {
                SM2KeyPairGenerator generator;
                passed = passed && (generator.getPublicKey().size() > 0);
                passed = passed && (generator.getPrivateKey().size() > 0);

                std::cout << generator.getPemPrivateKey() << std::endl;
            }
            if (passed) {
                std::cout << "testSM2KeyGen() passed " << std::endl;
            } else {
                std::cout << "testSM2KeyGen() failed " << std::endl;
            }
        }
        void testSM2KeyEncrypt() {
            bool passed = true;
            {
                std::string plainText = "hello world sm2";

                std::string privateKey = "308193020100301306072a8648ce3d020106082a811ccf5501822d047930770201010420837d4f5612081b224a0979b0a8de5553bbbdb11f2fb275a9be6d405d7c03dc91a00a06082a811ccf5501822da14403420004d016f02e97d8acf842d41e6c322f3450c56cb569ceb59eea89e292ff9d32a18a1e525f8513b184b0d3fb5537be258fb3df3f060e67698475c3a462791c0f7e7b";

                std::string publicKey = "3059301306072a8648ce3d020106082a811ccf5501822d03420004d016f02e97d8acf842d41e6c322f3450c56cb569ceb59eea89e292ff9d32a18a1e525f8513b184b0d3fb5537be258fb3df3f060e67698475c3a462791c0f7e7b";

                SM2PublicKeyEncryptor encryptor(publicKey, "hex", "");
                std::cout << encryptor.encryptToBase64(plainText) << std::endl;
                std::string encryptData = encryptor.encryptToHex(plainText);
                std::cout << encryptData << std::endl;
                for (int i = 0; i < encryptData.size(); ++i) {
                    std::cout << ((encryptData[i]) == 0x04 )<< std::endl;
                }
                std::string encrypt64Data = encryptor.encryptToBase64(plainText);

                SM2PrivateKeyDecryptor decryptor(privateKey, "hex", "");
                std::cout << decryptor.decryptFromBase64(encrypt64Data) << std::endl;

                std::string encryptData2 = "BMDU0eJgZrT7J+pLXciJriSMe7/mSW24DshtszYifzc5krY6b3tW+xqRjo76maa76iF6fwcl4ErBhCWyZF5KFWY0RZ+1+BGIZ0lwDwfCaP8rSl6qEgYmOOu/ctyDYFkyzLuYnhtK6tP7P8souhqr3g==";

                std::cout << encryptData2.length() << std::endl;

                std::cout << decryptor.decryptFromBase64(encryptData2) << std::endl;


            }
            if (passed) {
                std::cout << "testSM2KeyEncrypt() passed " << std::endl;
            } else {
                std::cout << "testSM2KeyEncrypt() failed " << std::endl;
            }

        }
    }
}
