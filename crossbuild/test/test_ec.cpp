//
// Created by baojian on 2025/8/19.
//

#include "test_ec.h"

#include <iostream>
#include <ostream>

#include "../common/base64.h"
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

        void testHKDFKeyGen() {
            bool passed = true;
            {
                ECKeyPairGenerator localGenerator("secp256r1");
                ECKeyPairGenerator remoteGenerator("secp256r1");

                ECDHSharedSecretGenerator localECDHSharedSecretGenerator(localGenerator.getBase64PrivateKey(), remoteGenerator.getBase64PublicKey(), "base64");
                ECDHSharedSecretGenerator remoteECDHSharedSecretGenerator(remoteGenerator.getBase64PrivateKey(), localGenerator.getBase64PublicKey(), "base64");
                std::string secret = localECDHSharedSecretGenerator.getGenSecret();
                HKDFSecretGenerator hkdfGenerator(secret, "test", "test-salt");

                std::cout << "------------ HKDFSecretGenerator check1  ------------" << std::endl;
                std::cout << hkdfGenerator.getGenSecretBase64() << std::endl;
            }
            {
                std::string secret = "test hkdf 2";
                std::string infoKey = "standard-hkdf-example";
                std::string salt = "hkdf-salt";
                HKDFSecretGenerator hkdfGenerator(secret, infoKey, salt);

                std::string expect_secret = "sHR+JXR3P75igX2NQoshQX5pErG+Pm50C1P3eUMzd4g=";

                std::cout << "------------ HKDFSecretGenerator check2  ------------" << std::endl;
                std::cout << hkdfGenerator.getGenSecretBase64() << std::endl;
                passed = passed && (hkdfGenerator.getGenSecretBase64() == expect_secret);
            }
            if (passed) {
                std::cout << "testHKDFKeyGen() passed " << std::endl;
            } else {
                std::cout << "testHKDFKeyGen() failed " << std::endl;
            }
        }

        void testECDSASigner() {
            bool passed = true;
            {
                ECKeyPairGenerator keyGenerator("secp256r1");
                ECDSAPrivateKeySigner signer(keyGenerator.getBase64PrivateKey(), "base64", "SHA256withECDSA");
                ECDSAPublicKeyVerifier verifier(keyGenerator.getBase64PublicKey(), "base64", "SHA256withECDSA");

                std::string plainText = "hello world ECDSA";

                std::cout << "------------  ECDSAPrivateKeySigner ECDSAPublicKeyVerifier  check1  ------------" << std::endl;
                std::cout << signer.signToBase64(plainText) << std::endl;
                passed = passed && (verifier.verifyBase64Sign(signer.signToBase64(plainText), plainText));
            }

            {
                //secp256r1

                std::string publicKey ="MIIBMzCB7AYHKoZIzj0CATCB4AIBATAsBgcqhkjOPQEBAiEA/////wAAAAEAAAAAAAAAAAAAAAD///////////////8wRAQg/////wAAAAEAAAAAAAAAAAAAAAD///////////////wEIFrGNdiqOpPns+u9VXaYhrxlHQawzFOw9jvOPD4n0mBLBEEEaxfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpZP40Li/hp/m47n60p8D54WK84zV2sxXs7LtkBoN79R9QIhAP////8AAAAA//////////+85vqtpxeehPO5ysL8YyVRAgEBA0IABA6j78Q7dzIQ3MjXnYswtPPj9jU7ar2xh04x4pzLQmT2MASK6koWxoeBpIOzbsmx0fYhtiMF8AWBblkvhg2tFys=";

                std::string privateKey = "MIICSwIBADCB7AYHKoZIzj0CATCB4AIBATAsBgcqhkjOPQEBAiEA/////wAAAAEAAAAAAAAAAAAAAAD///////////////8wRAQg/////wAAAAEAAAAAAAAAAAAAAAD///////////////wEIFrGNdiqOpPns+u9VXaYhrxlHQawzFOw9jvOPD4n0mBLBEEEaxfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpZP40Li/hp/m47n60p8D54WK84zV2sxXs7LtkBoN79R9QIhAP////8AAAAA//////////+85vqtpxeehPO5ysL8YyVRAgEBBIIBVTCCAVECAQEEIDEEwzh6+ClCMUnKz9s/l3c4ag+q64F9iDTczj8pV3s2oIHjMIHgAgEBMCwGByqGSM49AQECIQD/////AAAAAQAAAAAAAAAAAAAAAP///////////////zBEBCD/////AAAAAQAAAAAAAAAAAAAAAP///////////////AQgWsY12Ko6k+ez671VdpiGvGUdBrDMU7D2O848PifSYEsEQQRrF9Hy4SxCR/i85uVjpEDydwN9gS3rM6D0oTlF2JjClk/jQuL+Gn+bjufrSnwPnhYrzjNXazFezsu2QGg3v1H1AiEA/////wAAAAD//////////7zm+q2nF56E87nKwvxjJVECAQGhRANCAAQOo+/EO3cyENzI152LMLTz4/Y1O2q9sYdOMeKcy0Jk9jAEiupKFsaHgaSDs27JsdH2IbYjBfAFgW5ZL4YNrRcr";

                ECDSAPrivateKeySigner signer(privateKey , "base64", "SHA256withECDSA");
                ECDSAPublicKeyVerifier verifier(publicKey, "base64", "SHA256withECDSA");

                std::string plainText = "Hello ECC Signature";
                std::string java_sign = "MEQCH1sCTgJCrE2Cv1snOOb+41U82VFqBPf25qHEdzpIa0ECIQC5I0Vuh5qsPQTMXoYQfX+OOT3mDIgP612yeNEif85h+g==";

                std::cout << "------------  ECDSAPrivateKeySigner ECDSAPublicKeyVerifier check2 with java   ------------" << std::endl;
                std::cout << signer.signToBase64(plainText) << std::endl;
                passed = passed && (verifier.verifyBase64Sign(signer.signToBase64(plainText), plainText));

                passed = passed && (verifier.verifyBase64Sign(java_sign, plainText));
            }

            {
                ECKeyPairGenerator keyGenerator("secp521r1");
                ECDSAPrivateKeySigner signer(keyGenerator.getBase64PrivateKey(), "base64", "SHA512withECDSA");
                ECDSAPublicKeyVerifier verifier(keyGenerator.getBase64PublicKey(), "base64", "SHA512withECDSA");

                std::string plainText = "hello world ECDSA";

                std::cout << "------------  ECDSAPrivateKeySigner ECDSAPublicKeyVerifier secp521r1 check1  ------------" << std::endl;
                std::cout << signer.signToBase64(plainText) << std::endl;
                passed = passed && (verifier.verifyBase64Sign(signer.signToBase64(plainText), plainText));
            }

            {
                ECKeyPairGenerator keyGenerator("secp256k1");
                ECDSAPrivateKeySigner signer(keyGenerator.getBase64PrivateKey(), "base64", "SHA256withECDSA");
                ECDSAPublicKeyVerifier verifier(keyGenerator.getBase64PublicKey(), "base64", "SHA256withECDSA");

                std::string plainText = "hello world ECDSA";

                std::cout << "------------  ECDSAPrivateKeySigner ECDSAPublicKeyVerifier secp256k1 check1  ------------" << std::endl;
                std::cout << signer.signToBase64(plainText) << std::endl;
                passed = passed && (verifier.verifyBase64Sign(signer.signToBase64(plainText), plainText));
            }

            if (passed) {
                std::cout << "testECDSASigner() passed " << std::endl;
            } else {
                std::cout << "testECDSASigner() failed " << std::endl;
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
