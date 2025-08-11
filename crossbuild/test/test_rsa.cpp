//
// Created by baojian on 25-8-5.
//

#include "test_rsa.h"

#include <iostream>
#include <sstream>

using namespace camel::crypto;

namespace camel {
    namespace crypto {
        void testRsaGenerateKey() {
            bool passed = true;
            RSAKeyPairGenerator rsa;
            {
                auto derPublicKey = rsa.getPublicKey();
                auto hexPublicKey = rsa.getHexPublicKey();
                auto base64PublicKey = rsa.getBase64NewLinePublicKey();
                auto base64OneLinePublicKey = rsa.getBase64PublicKey();
                auto pemPublicKey = rsa.getPemPublicKey();
                passed = passed && base64PublicKey == base64_encode_new_line(derPublicKey);
                passed = passed && derPublicKey == base64_decode(base64OneLinePublicKey);
                passed = passed && hexPublicKey == hex_encode(derPublicKey);
                passed = passed && (pemPublicKey.find(base64PublicKey) != std::string::npos) ;
                passed = passed && (pemPublicKey.find("-----BEGIN PUBLIC KEY-----") != std::string::npos) ;
            }

            {
                auto derPrivateKey = rsa.getPrivateKey();
                auto hexPrivateKey = rsa.getHexPrivateKey();
                auto base64PrivateKey = rsa.getBase64NewLinePrivateKey();
                auto base64OneLinePrivateKey = rsa.getBase64PrivateKey();
                auto pemPrivateKey = rsa.getPemPrivateKey();
                passed = passed && base64PrivateKey == base64_encode_new_line(derPrivateKey);
                passed = passed && derPrivateKey == base64_decode(base64OneLinePrivateKey);
                passed = passed && hexPrivateKey == hex_encode(derPrivateKey);
                passed = passed && (pemPrivateKey.find(base64PrivateKey) != std::string::npos);
                passed = passed && (pemPrivateKey.find("-----BEGIN PRIVATE KEY-----") != std::string::npos) ;
            }

            if (passed) {
                std::cout << "testRsaGenerateKey() passed " << std::endl;
            } else {
                std::cout << "testRsaGenerateKey() failed " << std::endl;
            }
        }




    }
}
