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
            *  代码兼容 OpenSSL 支持的所有椭圆曲线，包括：
            *  NIST 曲线：secp256r1（P-256）、secp384r1（P-384）、secp521r1（P-521）
            *  区块链常用：secp256k1
            *  Edwards 曲线：ed25519、x25519、ed448、x448
            *  国密曲线：SM2（需 OpenSSL 支持国密算法）
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