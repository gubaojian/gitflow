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
                std::string encrypt64Data = encryptor.encryptToBase64(plainText);

                std::cout << "encryptor ANS1 result" << std::endl;
                std::cout << encrypt64Data << std::endl;

                SM2PrivateKeyDecryptor decryptor(privateKey, "hex", "");
                std::cout << decryptor.decryptFromBase64(encrypt64Data) << std::endl;

                passed = passed && plainText == decryptor.decryptFromBase64(encrypt64Data);

                std::string encryptData2 = "BMDU0eJgZrT7J+pLXciJriSMe7/mSW24DshtszYifzc5krY6b3tW+xqRjo76maa76iF6fwcl4ErBhCWyZF5KFWY0RZ+1+BGIZ0lwDwfCaP8rSl6qEgYmOOu/ctyDYFkyzLuYnhtK6tP7P8souhqr3g==";


                std::cout << "decryptor java C1C2C3 result" << std::endl;
                //std::cout << decryptor.decryptFromBase64(encryptData2) << std::endl;
                //passed = passed && plainText == decryptor.decryptFromBase64(encryptData2);


            }
            {
                std::string plainText = "hello world sm2";
                std::string dataModeFlag = "C1C2C3";
                std::string privateKey = "308193020100301306072a8648ce3d020106082a811ccf5501822d047930770201010420837d4f5612081b224a0979b0a8de5553bbbdb11f2fb275a9be6d405d7c03dc91a00a06082a811ccf5501822da14403420004d016f02e97d8acf842d41e6c322f3450c56cb569ceb59eea89e292ff9d32a18a1e525f8513b184b0d3fb5537be258fb3df3f060e67698475c3a462791c0f7e7b";
                std::string publicKey = "3059301306072a8648ce3d020106082a811ccf5501822d03420004d016f02e97d8acf842d41e6c322f3450c56cb569ceb59eea89e292ff9d32a18a1e525f8513b184b0d3fb5537be258fb3df3f060e67698475c3a462791c0f7e7b";

                SM2PublicKeyEncryptor encryptor(publicKey, "hex", dataModeFlag);
                std::cout << encryptor.encryptToBase64(plainText) << std::endl;
                std::string encrypt64Data = encryptor.encryptToBase64(plainText);

                std::cout << "encryptor result " << dataModeFlag << std::endl;
                std::cout << encrypt64Data << std::endl;

                SM2PrivateKeyDecryptor decryptor(privateKey, "hex", dataModeFlag);
                std::cout << decryptor.decryptFromBase64(encrypt64Data) << std::endl;
                passed = passed && plainText == decryptor.decryptFromBase64(encrypt64Data);

            }
            {
                std::string plainText = "hello world sm2";
                std::string dataModeFlag = "C1C3C2";
                std::string privateKey = "308193020100301306072a8648ce3d020106082a811ccf5501822d047930770201010420837d4f5612081b224a0979b0a8de5553bbbdb11f2fb275a9be6d405d7c03dc91a00a06082a811ccf5501822da14403420004d016f02e97d8acf842d41e6c322f3450c56cb569ceb59eea89e292ff9d32a18a1e525f8513b184b0d3fb5537be258fb3df3f060e67698475c3a462791c0f7e7b";
                std::string publicKey = "3059301306072a8648ce3d020106082a811ccf5501822d03420004d016f02e97d8acf842d41e6c322f3450c56cb569ceb59eea89e292ff9d32a18a1e525f8513b184b0d3fb5537be258fb3df3f060e67698475c3a462791c0f7e7b";

                SM2PublicKeyEncryptor encryptor(publicKey, "hex", dataModeFlag);
                std::cout << encryptor.encryptToBase64(plainText) << std::endl;
                std::string encrypt64Data = encryptor.encryptToBase64(plainText);

                std::cout << "encryptor result " << dataModeFlag << std::endl;
                std::cout << encrypt64Data << std::endl;

                SM2PrivateKeyDecryptor decryptor(privateKey, "hex", dataModeFlag);
                std::cout << decryptor.decryptFromBase64(encrypt64Data) << std::endl;
                passed = passed && plainText == decryptor.decryptFromBase64(encrypt64Data);

            }
            if (passed) {
                std::cout << "testSM2KeyEncrypt() passed " << std::endl;
            } else {
                std::cout << "testSM2KeyEncrypt() failed " << std::endl;
            }

        }

        void testSM2KeySigner() {
            bool passed = true;
            {
                std::string plainText = "hello world sm2";

                std::string privateKey = "308193020100301306072a8648ce3d020106082a811ccf5501822d047930770201010420ae56db268e4062dde776894bab0aa2782ddbafc9ee4cbe9d12bbf38aa5e2aa95a00a06082a811ccf5501822da14403420004059626c6d2514767f90763d79583a1d9387f219e438b23ee991d6e1c854a02af1a1963d968cb979e4a5f3b46f958208b15bb96354de976dc67e87d386edb1bb4";

                std::string publicKey = "3059301306072a8648ce3d020106082a811ccf5501822d03420004059626c6d2514767f90763d79583a1d9387f219e438b23ee991d6e1c854a02af1a1963d968cb979e4a5f3b46f958208b15bb96354de976dc67e87d386edb1bb4";

                SM2PrivateKeySigner signer(privateKey, "hex", "");
                SM2PublicKeyVerifier verifier(publicKey, "hex", "");
                std::cout << "------------ SM2 sign result ------------" << std::endl;
                std::cout << signer.signToBase64(plainText) << std::endl;
                passed = passed && verifier.verifySign(signer.signToBase64(plainText), plainText);

                std::string java_sign_hex = "304402203cf3cb54260d4476c5759c1e2189a6e767bb0e642ffb5610d2e7fc1c0585046502207cc8703f150dea4739e5823e5e004226f268acaf480ec4c061da9bc75fa17a16";

                passed = passed && verifier.verifyHexSign(java_sign_hex, plainText);

            }
            if (passed) {
                std::cout << "testSM2KeySigner() passed " << std::endl;
            } else {
                std::cout << "testSM2KeySigner() failed " << std::endl;
            }
        }
    }
}
