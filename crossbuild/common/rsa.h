//
// Created by baojian on 25-8-5.
//

#ifndef CAMEL_RSA_H
#define CAMEL_RSA_H
#include "config.h"
#include "hex.h"
#include "base64.h"
#include <string>
#include <openssl/types.h>


namespace camel {
    namespace crypto {


        EVP_PKEY* RSAPublicKeyFromPem(const std::string& pemKey);
        EVP_PKEY* RSAPublicKeyFromBase64(const std::string& base64Key);
        EVP_PKEY* RSAPublicKeyFromHex(const std::string& hexKey);
        EVP_PKEY* RSAPublicKeyFromDer(const std::string& derKey);
        EVP_PKEY* RSAPublicKeyFromDerByBio(const std::string& derKey);

        EVP_PKEY* RSAPrivateKeyFromPem(const std::string& pemKey);
        EVP_PKEY* RSAPrivateKeyFromBase64(const std::string& base64Key);
        EVP_PKEY* RSAPrivateKeyFromHex(const std::string& hexKey);
        EVP_PKEY* RSAPrivateKeyFromDer(const std::string& derKey);
        EVP_PKEY* RSAPrivateKeyFromDerByBio(const std::string& derKey);



        class RSAKeyPairGenerator {
            public:
                explicit RSAKeyPairGenerator(int keyLength=2048);
                ~RSAKeyPairGenerator();
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
             private:
                void clean();
          private:
            EVP_PKEY_CTX* ctx = nullptr;
            EVP_PKEY* pkey = nullptr;
        };

        constexpr auto  RSA_PKCS1Padding = "PKCS1Padding";
        constexpr auto  RSA_OAEPPadding = "OAEPPadding";
        constexpr auto  RSA_OAEPwithSHA_256andMGF1Padding = "OAEPwithSHA-256andMGF1Padding";
        constexpr auto  RSA_OAEPwithSHA_384andMGF1Padding = "OAEPwithSHA-384andMGF1Padding";
        constexpr auto  RSA_OAEPwithSHA_512andMGF1Padding = "OAEPwithSHA-512andMGF1Padding";

        class RSAPublicKeyEncryptor {
           public:
               /**
               * format = "pem", "hex", "base64", "der"
               * OAEPPadding PKCS1Padding default
               * OAEPwithSHA-256andMGF1Padding
               * OAEPwithSHA-384andMGF1Padding
               * OAEPwithSHA-512andMGF1Padding
                */
               explicit RSAPublicKeyEncryptor(const std::string& publicKey,
                    const std::string& format = "pem",
                    const std::string& paddings= RSA_PKCS1Padding);

               ~RSAPublicKeyEncryptor() {
                   if (pKey != nullptr) {
                       EVP_PKEY_free(pKey);
                       pKey = nullptr;
                   }
               }

               RSAPublicKeyEncryptor(const RSAPublicKeyEncryptor&) = delete;
               RSAPublicKeyEncryptor& operator=(const RSAPublicKeyEncryptor&) = delete;

            public:
               std::string encrypt(const std::string_view& plainText) const;
               std::string encryptToBase64(const std::string_view& plainText) const;
               std::string encryptToHex(const std::string_view& plainText) const;
            private:
              EVP_PKEY* pKey = nullptr;
              std::string publicKey;
              std::string format;
              std::string paddings;
        };

        class RSAPrivateKeyDecryptor {
        public:
            /**
              * format = "pem", "hex", "base64", "der"
              * OAEPPadding PKCS1Padding default
              * OAEPwithSHA-256andMGF1Padding
              * OAEPwithSHA-384andMGF1Padding
              * OAEPwithSHA-512andMGF1Padding
               */
            explicit RSAPrivateKeyDecryptor(const std::string& publicKey,
                  const std::string& format = "pem",
                  const std::string& paddings = RSA_PKCS1Padding);
            ~RSAPrivateKeyDecryptor() {
                if (pKey != nullptr) {
                    EVP_PKEY_free(pKey);
                    pKey = nullptr;
                }
            }
        public:
            std::string decrypt(const std::string_view& encryptedData) const;
            std::string decryptFromBase64(const std::string_view& base64EncryptedText) const;
            std::string decryptFromHex(const std::string_view& hexEncryptedText) const;
        private:
            EVP_PKEY* pKey = nullptr;
            std::string privateKey;
            std::string format;
            std::string paddings;
        };





    }
}




#endif //CAMEL_RSA_H
