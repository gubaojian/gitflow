//
// Created by baojian on 25-8-14.
//

#include "demo_aes.h"
#include <iostream>
#include <sstream>
#include "../common/aes.h"
#include "../common/file_utils.h"

namespace camel {
    namespace crypto {
        void demoAesGenerateKey() {
            {
                AESKeyGenerator aesKey(128);
                {
                    std::cout <<"--------------AES 128 KEY --------------" << std::endl;
                    std::cout << aesKey.getHexKey() << std::endl;
                    std::cout << aesKey.getBase64Key() << std::endl;
                }
                FileUtils::writeFile("aes_128_key.txt", aesKey.getBase64Key(), true);
            }
            AESKeyGenerator aesKey(256);
            {
                std::cout <<"--------------AES 256 KEY --------------" << std::endl;
                std::cout << aesKey.getHexKey() << std::endl;
                std::cout << aesKey.getBase64Key() << std::endl;
            }
            FileUtils::writeFile("aes_256_key.txt", aesKey.getBase64Key(), true);
        }

        void demoAesEncrypt() {
            std::cout <<"--------------AES ENCRYPT ---------------" << std::endl;
            std::string secret = "E7BpQCZlD1hNJYeDUk4RBw==";
            {
                std::string encrypt_data = "rfr0VnPzg929JoCSBtlPrw==";
                AESDecryptor decryptor("AES-ECB", secret, "base64");

                std::cout << decryptor.decryptFromBase64(encrypt_data) << std::endl;
            }

            {
                std::string encrypt_data = "zae5jVqbThlULDChZnLQ3S0trsirtK30bNRqVtnsLWg=";
                AESDecryptor decryptor("AES-CBC", secret, "base64");

                std::cout << decryptor.decryptFromBase64(encrypt_data) << std::endl;
            }

            {
                std::string encrypt_data = "8Zq8VyrE+LKBcDk6+X+34pW8u8tM02fIbQnC5mKLLg==";
                AESDecryptor decryptor("AES-CFB", secret, "base64");

                std::cout << decryptor.decryptFromBase64(encrypt_data) << std::endl;
            }

            {
                std::string encrypt_data = "8UF1bVkvDko+Wg6Qsqvg8Ee8eqk/S/+oTtHlMG4JWg==";
                AESDecryptor decryptor("AES-CTR", secret, "base64");

                std::cout << decryptor.decryptFromBase64(encrypt_data) << std::endl;
            }



            {
                std::string encrypt_data = "ilctqYJZDKYLC5d1kb3vY4jb8Exr4DZyEV+6Pi2Hkw==";
                AESDecryptor decryptor("AES-OFB", secret, "base64");

                std::cout << decryptor.decryptFromBase64(encrypt_data) << std::endl;
            }



            {
                std::string encrypt_data = "76lnBEA54erCyLyEtYJ2CDnSjy8/STN2h0QaFiulkiSpDp0uLZ5AtUghuw==";
                AESDecryptor decryptor("AES-GCM", secret, "base64");
                std::cout << "-----------------------GCM--------------------------" << std::endl;
                std::cout << decryptor.decryptFromBase64(encrypt_data) << std::endl;
            }

            {
                std::string encrypt_data = "tQBYHdKDYKUOJkKHspbp5JBbpsCUZi3P3FffN1GP4wxOeCR6V65RrVPyYA==";
                AESDecryptor decryptor("AES-GCM-SIV", secret, "base64");
                std::cout << "-----------------------GCM-SIV--------------------------" << std::endl;
                std::cout << decryptor.decryptFromBase64(encrypt_data) << std::endl;
            }

            {
                std::string encrypt_data = "YWFhYWFhYWFhYWFhofv7O7/3JKi93yz2dlkhE2IS5A0lj8IkM6pgqqanTw==";
                AESDecryptor decryptor("AES-CCM", secret, "base64");
                std::cout << "-----------------------CCM--------------------------" << std::endl;
                std::cout << decryptor.decryptFromBase64(encrypt_data) << std::endl;
            }











        }
    }
}
