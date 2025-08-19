//
// Created by baojian on 2025/8/19.
//

#include "test_ec.h"

#include <iostream>
#include <ostream>

#include "../common/ec.h"


namespace camel {
    namespace crypto {
        void testEcKeyGen() {
            bool passed = true;
            {
                ECKeyPairGenerator generator("secp256r1");
                passed = passed && (generator.getPublicKey().size() > 0);
                passed = passed && (generator.getPrivateKey().size() > 0);
            }
            {
                ECKeyPairGenerator generator("P-256");
                passed = passed && (generator.getPublicKey().size() > 0);
                passed = passed && (generator.getPrivateKey().size() > 0);
            }
            {
                ECKeyPairGenerator generator("P-384");
                passed = passed && (generator.getPublicKey().size() > 0);
                passed = passed && (generator.getPrivateKey().size() > 0);
            }

            {
                ECKeyPairGenerator generator("P-521");
                passed = passed && (generator.getPublicKey().size() > 0);
                passed = passed && (generator.getPrivateKey().size() > 0);
            }

            ECKeyPairGenerator generator("secp256r1");
            std::cout << generator.getPemPublicKey() << std::endl;
            std::cout << generator.getPemPrivateKey() << std::endl;

            if (passed) {
                std::cout << "testEcKeyGen() passed " << std::endl;
            } else {
                std::cout << "testEcKeyGen() failed " << std::endl;
            }


        }

        void testEcKeyEncrypt() {
            bool passed = true;
            {
                std::string plainText = "hello world ec";
                ECKeyPairGenerator generator("SM2");
                ECPublicKeyEncryptor encryptor(generator.getPemPublicKey(), "pem", "AES-256-GCM");
                std::cout << encryptor.encryptToBase64(plainText) << std::endl;
            }
            {
                std::string plainText = "hello world ec";
                ECKeyPairGenerator generator("Ed25519");
                ECPublicKeyEncryptor encryptor(generator.getPemPublicKey(), "pem", "AES-256-GCM");
                std::cout << encryptor.encryptToBase64(plainText) << std::endl;
            }
            if (passed) {
                std::cout << "testEcKeyEncrypt() passed " << std::endl;
            } else {
                std::cout << "testEcKeyEncrypt() failed " << std::endl;
            }
        }

    }
}
