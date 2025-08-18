//
// Created by baojian on 2025/8/18.
//

#ifndef CAMEL_ELLIPTIC_CURVE_H
#define CAMEL_ELLIPTIC_CURVE_H
#include <string_view>
#include <openssl/types.h>

namespace camel {
    namespace crypto {

        class ECKeyPairGenerator {
        public:
            /**
             *
             *  ecp256r1 secp284r1 ed25519 secp256k1 SM2  x25519 ed448
             */
            explicit ECKeyPairGenerator(const std::string_view& curveName = "secp256r1"); //1024 2048 4096
            ~ECKeyPairGenerator();
        public:
            std::string getPublicKey();
            std::string getPrivateKey();
            std::string getHexPublicKey();
            std::string getHexPrivateKey();
            std::string getBase64NewLinePublicKey();  //same with pem
            std::string getBase64NewLinePrivateKey(); //same with pem
            std::string getBase64PublicKey();
            std::string getBase64PrivateKey();
            std::string getPemPublicKey();
            std::string getPemPrivateKey();
        public:
            ECKeyPairGenerator(const ECKeyPairGenerator&) = delete;
            ECKeyPairGenerator& operator=(const ECKeyPairGenerator&) = delete;
        private:
            void clean();
        private:
            EVP_PKEY_CTX* ctx = nullptr;
            EVP_PKEY* pkey = nullptr;
        };

    }
}


#endif //CAMEL_ELLIPTIC_CURVE_H