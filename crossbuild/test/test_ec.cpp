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
                std::cout << "------------ ECKeyPairGenerator secp256r1 check1  ------------" << std::endl;
                passed = passed && (generator.getPublicKey().size() > 0);
                passed = passed && (generator.getPrivateKey().size() > 0);
                std::cout << generator.getBase64PublicKey() << std::endl;
                std::cout << generator.getBase64PrivateKey() << std::endl;
            }
            {
                ECKeyPairGenerator generator("P-256");
                std::cout << "------------ ECKeyPairGenerator P-256 check1  ------------" << std::endl;
                passed = passed && (generator.getPublicKey().size() > 0);
                passed = passed && (generator.getPrivateKey().size() > 0);
                std::cout << generator.getBase64PublicKey() << std::endl;
                std::cout << generator.getBase64PrivateKey() << std::endl;
            }
            {
                ECKeyPairGenerator generator("P-384");
                std::cout << "------------ ECKeyPairGenerator P-384 check1  ------------" << std::endl;
                passed = passed && (generator.getPublicKey().size() > 0);
                passed = passed && (generator.getPrivateKey().size() > 0);
                std::cout << generator.getBase64PublicKey() << std::endl;
                std::cout << generator.getBase64PrivateKey() << std::endl;
            }

            {
                ECKeyPairGenerator generator("P-521");
                std::cout << "------------ ECKeyPairGenerator P-521 check1  ------------" << std::endl;
                passed = passed && (generator.getPublicKey().size() > 0);
                passed = passed && (generator.getPrivateKey().size() > 0);
                std::cout << generator.getBase64PublicKey() << std::endl;
                std::cout << generator.getBase64PrivateKey() << std::endl;
            }

            {
                ECKeyPairGenerator generator("secp256k1");
                std::cout << "------------ ECKeyPairGenerator secp256k1 check1  ------------" << std::endl;
                passed = passed && (generator.getPublicKey().size() > 0);
                passed = passed && (generator.getPrivateKey().size() > 0);
                std::cout << generator.getBase64PublicKey() << std::endl;
                std::cout << generator.getBase64PrivateKey() << std::endl;
            }

            {
                ECKeyPairGenerator generator("ED25519");
                std::cout << "------------ ECKeyPairGenerator ED25519 check1  ------------" << std::endl;
                passed = passed && (generator.getPublicKey().size() > 0);
                passed = passed && (generator.getPrivateKey().size() > 0);
                std::cout << generator.getBase64PublicKey() << std::endl;
                std::cout << generator.getBase64PrivateKey() << std::endl;
            }

            {
                ECKeyPairGenerator generator("ED448");
                std::cout << "------------ ECKeyPairGenerator ED448 check1  ------------" << std::endl;
                passed = passed && (generator.getPublicKey().size() > 0);
                passed = passed && (generator.getPrivateKey().size() > 0);
                std::cout << generator.getBase64PublicKey() << std::endl;
                std::cout << generator.getBase64PrivateKey() << std::endl;
            }

            {
                ECKeyPairGenerator generator("X25519");
                std::cout << "------------ ECKeyPairGenerator X25519 check1  ------------" << std::endl;
                passed = passed && (generator.getPublicKey().size() > 0);
                passed = passed && (generator.getPrivateKey().size() > 0);
                std::cout << generator.getBase64PublicKey() << std::endl;
                std::cout << generator.getBase64PrivateKey() << std::endl;
            }

            {
                ECKeyPairGenerator generator("X448");
                std::cout << "------------ ECKeyPairGenerator X448 check1  ------------" << std::endl;
                passed = passed && (generator.getPublicKey().size() > 0);
                passed = passed && (generator.getPrivateKey().size() > 0);
                std::cout << generator.getBase64PublicKey() << std::endl;
                std::cout << generator.getBase64PrivateKey() << std::endl;
            }



            if (passed) {
                std::cout << "testEcKeyGen() passed " << std::endl;
            } else {
                std::cout << "testEcKeyGen() failed " << std::endl;
            }

        }

        void testEcDHKeyGen() {
            bool passed = true;
            {
                ECKeyPairGenerator localGenerator("secp256r1");
                ECKeyPairGenerator remoteGenerator("secp256r1");

                ECDHSharedSecretGenerator localECDHSharedSecretGenerator(localGenerator.getBase64PrivateKey(), remoteGenerator.getBase64PublicKey(), "base64");
                ECDHSharedSecretGenerator remoteECDHSharedSecretGenerator(remoteGenerator.getBase64PrivateKey(), localGenerator.getBase64PublicKey(), "base64");

                passed = passed && (!localECDHSharedSecretGenerator.getGenSecret().empty());
                passed = passed && (!remoteECDHSharedSecretGenerator.getGenSecret().empty());
                passed = passed && (localECDHSharedSecretGenerator.getGenSecret() == remoteECDHSharedSecretGenerator.getGenSecret());
                std::cout << "------------ ECDHSharedSecretGenerator secp256r1 check1  ------------" << std::endl;
                std::cout << localECDHSharedSecretGenerator.getGenSecretBase64() << std::endl;
            }

            {
                std::string localPrivateKey = "MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCARygg7cu8Xokgh3m19Uv+FF+QwIrwzVv7+JEi5LX3EyA==";
                std::string localPublicKey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAErYHCY1/SriZiQijtlLeg6QD8FGUT/l1x3NLpkXmk427U5XI/KnuLE0KcsOjTgrxqDNqj5ZK27VT/7W8nhcoYJw==";
                std::string remotePrivateKey = "MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCAmQxcqYh8FF4gQ6tQhleVC78ovLu7nywYkMNxO8sz+SQ==";
                std::string remotePublicKey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE4eC1fBvoZdpYsC6vrJxhl/KvsPnLQvEFIlFx4QkSFtTboxXYc0Kudf8mbTxX+1GIgfAuLEyFvmhZDbffdv+2ng==";

                ECDHSharedSecretGenerator localECDHSharedSecretGenerator(localPrivateKey, remotePublicKey, "base64");
                ECDHSharedSecretGenerator remoteECDHSharedSecretGenerator(remotePrivateKey, localPublicKey, "base64");

                std::string expect_secret_base64 = "KeV8qKYFPVDL5wYbz2AhX4gf0Dd1TigibvTJ2UySZC0=";

                passed = passed && (!localECDHSharedSecretGenerator.getGenSecret().empty());
                passed = passed && (!remoteECDHSharedSecretGenerator.getGenSecret().empty());
                passed = passed && (localECDHSharedSecretGenerator.getGenSecret() == remoteECDHSharedSecretGenerator.getGenSecret());
                passed = passed && (localECDHSharedSecretGenerator.getGenSecretBase64() == expect_secret_base64);

                std::cout << "------------ ECDHSharedSecretGenerator check2 with java ------------" << std::endl;
                std::cout << localECDHSharedSecretGenerator.getGenSecretBase64() << std::endl;
            }


            {
                ECKeyPairGenerator localGenerator("secp521r1");
                ECKeyPairGenerator remoteGenerator("secp521r1");

                ECDHSharedSecretGenerator localECDHSharedSecretGenerator(localGenerator.getBase64PrivateKey(), remoteGenerator.getBase64PublicKey(), "base64");
                ECDHSharedSecretGenerator remoteECDHSharedSecretGenerator(remoteGenerator.getBase64PrivateKey(), localGenerator.getBase64PublicKey(), "base64");

                passed = passed && (!localECDHSharedSecretGenerator.getGenSecret().empty());
                passed = passed && (!remoteECDHSharedSecretGenerator.getGenSecret().empty());
                passed = passed && (localECDHSharedSecretGenerator.getGenSecret() == remoteECDHSharedSecretGenerator.getGenSecret());
                std::cout << "------------ ECDHSharedSecretGenerator secp521r1 check1  ------------" << std::endl;
                std::cout << localECDHSharedSecretGenerator.getGenSecretBase64() << std::endl;
            }

            {
                ECKeyPairGenerator localGenerator("secp256k1");
                ECKeyPairGenerator remoteGenerator("secp256k1");

                ECDHSharedSecretGenerator localECDHSharedSecretGenerator(localGenerator.getBase64PrivateKey(), remoteGenerator.getBase64PublicKey(), "base64");
                ECDHSharedSecretGenerator remoteECDHSharedSecretGenerator(remoteGenerator.getBase64PrivateKey(), localGenerator.getBase64PublicKey(), "base64");

                passed = passed && (!localECDHSharedSecretGenerator.getGenSecret().empty());
                passed = passed && (!remoteECDHSharedSecretGenerator.getGenSecret().empty());
                passed = passed && (localECDHSharedSecretGenerator.getGenSecret() == remoteECDHSharedSecretGenerator.getGenSecret());
                std::cout << "------------ ECDHSharedSecretGenerator secp256k1 check1  ------------" << std::endl;
                std::cout << localECDHSharedSecretGenerator.getGenSecretBase64() << std::endl;
            }


            {
                ECKeyPairGenerator localGenerator("secp256k1");
                ECKeyPairGenerator remoteGenerator("secp256k1");

                ECDHSharedSecretGenerator localECDHSharedSecretGenerator(localGenerator.getBase64PrivateKey(), remoteGenerator.getBase64PublicKey(), "base64");
                ECDHSharedSecretGenerator remoteECDHSharedSecretGenerator(remoteGenerator.getBase64PrivateKey(), localGenerator.getBase64PublicKey(), "base64");

                passed = passed && (!localECDHSharedSecretGenerator.getGenSecret().empty());
                passed = passed && (!remoteECDHSharedSecretGenerator.getGenSecret().empty());
                passed = passed && (localECDHSharedSecretGenerator.getGenSecret() == remoteECDHSharedSecretGenerator.getGenSecret());
                std::cout << "------------ ECDHSharedSecretGenerator secp256k1 check1  ------------" << std::endl;
                std::cout << localECDHSharedSecretGenerator.getGenSecretBase64() << std::endl;
            }

            {
                ECKeyPairGenerator localGenerator("x25519");
                ECKeyPairGenerator remoteGenerator("x25519");

                ECDHSharedSecretGenerator localECDHSharedSecretGenerator(localGenerator.getBase64PrivateKey(), remoteGenerator.getBase64PublicKey(), "base64");
                ECDHSharedSecretGenerator remoteECDHSharedSecretGenerator(remoteGenerator.getBase64PrivateKey(), localGenerator.getBase64PublicKey(), "base64");

                passed = passed && (!localECDHSharedSecretGenerator.getGenSecret().empty());
                passed = passed && (!remoteECDHSharedSecretGenerator.getGenSecret().empty());
                passed = passed && (localECDHSharedSecretGenerator.getGenSecret() == remoteECDHSharedSecretGenerator.getGenSecret());
                std::cout << "------------ ECDHSharedSecretGenerator x25519 check1  ------------" << std::endl;
                std::cout << localECDHSharedSecretGenerator.getGenSecretBase64() << std::endl;
            }

            {
                ECKeyPairGenerator localGenerator("x448");
                ECKeyPairGenerator remoteGenerator("x448");

                ECDHSharedSecretGenerator localECDHSharedSecretGenerator(localGenerator.getBase64PrivateKey(), remoteGenerator.getBase64PublicKey(), "base64");
                ECDHSharedSecretGenerator remoteECDHSharedSecretGenerator(remoteGenerator.getBase64PrivateKey(), localGenerator.getBase64PublicKey(), "base64");

                passed = passed && (!localECDHSharedSecretGenerator.getGenSecret().empty());
                passed = passed && (!remoteECDHSharedSecretGenerator.getGenSecret().empty());
                passed = passed && (localECDHSharedSecretGenerator.getGenSecret() == remoteECDHSharedSecretGenerator.getGenSecret());
                std::cout << "------------ ECDHSharedSecretGenerator x448 check1  ------------" << std::endl;
                std::cout << localECDHSharedSecretGenerator.getGenSecretBase64() << std::endl;
            }




            if (passed) {
                std::cout << "testEcDHKeyGen() passed " << std::endl;
            } else {
                std::cout << "testEcDHKeyGen() failed " << std::endl;
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
