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
            {
                std::string plainText = "hello world";
                std::cout <<"short text demo " << std::endl;
                std::cout << encryptor.encryptToHex(plainText) << std::endl;
                std::cout << encryptor.encryptToBase64(plainText) << std::endl;
            }
            {
                std::string longPlainText = "hello world";
                for (int i=0; i<1024; i++) {
                    longPlainText.append(std::to_string(i));
                    longPlainText.append("_");
                }
                std::cout <<"long text demo " << std::endl;
                std::cout << encryptor.encryptToHex(longPlainText) << std::endl;
                std::cout << encryptor.encryptToBase64(longPlainText) << std::endl;

            }

        }



    }
}
