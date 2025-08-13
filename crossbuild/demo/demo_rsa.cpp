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
            RSAPublicKeyEncryptor encryptorPem(rsa.getPemPublicKey());
            RSAPrivateKeyDecryptor decryptorPem(rsa.getPemPrivateKey());
            RSAPublicKeyEncryptor encryptorDer(rsa.getPublicKey(), "der");
            RSAPrivateKeyDecryptor decryptorDer(rsa.getPrivateKey(), "der");
            RSAPublicKeyEncryptor encryptorHex(rsa.getHexPublicKey(), "hex");
            RSAPrivateKeyDecryptor decryptorHex(rsa.getHexPrivateKey(), "hex");
            RSAPublicKeyEncryptor encryptorBase64(rsa.getBase64NewLinePublicKey(), "base64");
            RSAPrivateKeyDecryptor decryptorBase64(rsa.getBase64NewLinePrivateKey(), "base64");
            {
                std::string plainText = "hello world";
                std::cout <<"short text demo " << std::endl;
                std::string encryptedTextPem = encryptorPem.encrypt(plainText);
                std::string encryptedTextDer = encryptorDer.encrypt(plainText);
                std::string encryptedTextHex = encryptorHex.encrypt(plainText);
                std::string encryptedTextBase64 = encryptorBase64.encrypt(plainText);
                std::cout << encryptorPem.encryptToHex(plainText) << std::endl;
                std::cout << encryptorPem.encryptToBase64(plainText) << std::endl;
                std::cout << "pem result test result" << std::endl;
                std::cout << decryptorPem.decrypt(encryptedTextPem) << std::endl;
                std::cout << decryptorDer.decrypt(encryptedTextPem) << std::endl;
                std::cout << decryptorHex.decrypt(encryptedTextPem) << std::endl;
                std::cout << decryptorBase64.decrypt(encryptedTextPem) << std::endl;

                std::cout << "der result test result" << std::endl;
                std::cout << decryptorPem.decrypt(encryptedTextDer) << std::endl;
                std::cout << decryptorDer.decrypt(encryptedTextDer) << std::endl;
                std::cout << decryptorHex.decrypt(encryptedTextDer) << std::endl;
                std::cout << decryptorBase64.decrypt(encryptedTextDer) << std::endl;
            }

            {
                std::string longPlainText = "hello world";
                for (int i=0; i<1024; i++) {
                    longPlainText.append(std::to_string(i));
                    longPlainText.append("_");
                }
                std::cout <<"long text demo " << std::endl;
                std::string encryptedText = encryptorPem.encrypt(longPlainText);
                std::cout << encryptorPem.encryptToHex(longPlainText) << std::endl;
                std::cout << encryptorPem.encryptToBase64(longPlainText) << std::endl;
                std::cout << decryptorPem.decrypt(encryptedText) << std::endl;

            }

        }


        void demoRsaCryptPerf() {
            RSAKeyPairGenerator rsa;
            std::string publicKey = rsa.getPemPublicKey();
            RSAPublicKeyEncryptor encryptor(rsa.getPemPublicKey());
            RSAPrivateKeyDecryptor decryptor(rsa.getPemPrivateKey());
            int test_count = 5000;
            {
                auto start = std::chrono::high_resolution_clock::now();
                auto end = std::chrono::high_resolution_clock::now();
                auto used = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

                start = std::chrono::high_resolution_clock::now();
                std::string plainText = "hello world";
                for(int i=0; i<test_count; i++) {
                    std::string encryptedText = encryptor.encrypt(plainText);
                }
                end = std::chrono::high_resolution_clock::now();
                used = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
                std::cout << "rsa encrypt times per second " << ( (double)test_count)/(used.count()/1000.0f) << std::endl;
            }

            {
                auto start = std::chrono::high_resolution_clock::now();
                auto end = std::chrono::high_resolution_clock::now();
                auto used = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

                start = std::chrono::high_resolution_clock::now();
                std::string plainText = "hello world";

                for(int i=0; i<test_count; i++) {
                    std::string encryptedText = encryptor.encryptToHex(plainText);
                }
                end = std::chrono::high_resolution_clock::now();
                used = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
                std::cout << "rsa encrypt hex times per second " << ( (double)test_count)/(used.count()/1000.0f) << std::endl;

            }

            {
                auto start = std::chrono::high_resolution_clock::now();
                auto end = std::chrono::high_resolution_clock::now();
                auto used = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

                start = std::chrono::high_resolution_clock::now();
                std::string plainText = "hello world";
                for(int i=0; i<test_count; i++) {
                    std::string encryptedText = encryptor.encryptToBase64(plainText);
                }
                end = std::chrono::high_resolution_clock::now();
                used = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
                std::cout << "rsa encrypt base64 times per second " << ( (double)test_count)/(used.count()/1000.0f) << std::endl;

            }
        }

        void demoRsaDecryptPerf() {
            RSAKeyPairGenerator rsa;
            std::string publicKey = rsa.getPemPublicKey();
            RSAPublicKeyEncryptor encryptor(rsa.getPemPublicKey());
            RSAPrivateKeyDecryptor decryptor(rsa.getPemPrivateKey());
            int test_count = 5000;
            {
                auto start = std::chrono::high_resolution_clock::now();
                auto end = std::chrono::high_resolution_clock::now();
                auto used = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

                start = std::chrono::high_resolution_clock::now();
                std::string plainText = "hello world";
                std::string encryptedText = encryptor.encrypt(plainText);
                for(int i=0; i<test_count; i++) {
                    decryptor.decrypt(encryptedText);
                }
                end = std::chrono::high_resolution_clock::now();
                used = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
                std::cout << "rsa decrypt times per second " << ( (double)test_count)/(used.count()/1000.0f) << std::endl;
            }

            {
                auto start = std::chrono::high_resolution_clock::now();
                auto end = std::chrono::high_resolution_clock::now();
                auto used = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

                start = std::chrono::high_resolution_clock::now();
                std::string plainText = "hello world";
                std::string encryptedText = encryptor.encryptToHex(plainText);

                for(int i=0; i<test_count; i++) {
                    decryptor.decryptFromHex(encryptedText);
                }
                end = std::chrono::high_resolution_clock::now();
                used = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
                std::cout << "rsa decrypt hex times per second " << ( (double)test_count)/(used.count()/1000.0f) << std::endl;

            }

            {
                auto start = std::chrono::high_resolution_clock::now();
                auto end = std::chrono::high_resolution_clock::now();
                auto used = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

                start = std::chrono::high_resolution_clock::now();
                std::string plainText = "hello world";
                std::string encryptedText = encryptor.encryptToBase64(plainText);
                int test_count = 5000;
                for(int i=0; i<test_count; i++) {
                    decryptor.decryptFromBase64(encryptedText);
                }
                end = std::chrono::high_resolution_clock::now();
                used = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
                std::cout << "rsa decrypt base64 times per second " << ( (double)test_count)/(used.count()/1000.0f) << std::endl;

            }
        }


        void demoRsaSign() {
            std::string  plainText = "hello world rsa";
            std::string  privateKey = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC3LsCB4ElKKMhbxlSO06ohn3wk7QblfdevC9Jlqw7qL5s4wk7s3VvNyyKLgtMqwchq4EtC9gL+vEzMivVyOgfS8IT5so3ZwJkjcMrvy6822+Qk44hBNKr6fYVugXhoExtjXKAN2xFWM4M7qMbGRvzDcAFi2eWde4pVY9KaPYi33KEkM41umLsWXv8zp60FKrleXTlhx6gV8wu4bLGbTCOjIjRPQM7Sel9zsW6tY/7tLrms0pRVG9esNp+/Hb77dcjI22PlaH3luNS5jiy5nGznmdo1+HseFVQ8RK9CnpsdTot5ajctE/ND52i/UpJ4MkpcYFd0B+9tsVLdcPE1cttHAgMBAAECggEABi7JyJhtYNdni9Fx4TA7uc7MPeLSLMTGlt3rSAsyAa2Bq7TDPTNredK1Y8gSoIrR3OmdILF1AGwSm4TFLAnRYclEc7kXGJZrlMqlztotG8joNmaHnsvMSZAbBNPR4JFkh0IFFPKj7yjl8QmNS/vxZBdPtKpuGZal4KPx48rX5ny5MBxjtaFW+eBK9Dla+1EqiuFHOU1uIibbNHDouS8g5wDFmRwFL+nrWgv9xSGj7BPfkFi0mpfGN6rTZeJQBlgzLCx4BRxcD8P62hOW0/sMiKORnSvDtWu9e6lA9qAidmzG8QyHkwz/u+BFFdbPB/PQUVw8uzVTJzvcwASumCRxYQKBgQDCrS1oPsazdixBedrADHbNP4njxrCCLZ9jJ5jazepgVCYSNGcM0YjHr6PfCAseEKT8BXpFDVVy5UR3jhZS+XasTVQl34cXUgZjIkFqSgLHPkeyo1p/QXi4HQNjBpQfpjrq5TpDyBLbfZ6Z8NLlXCtIcrVpdDrWP3jvj3MtFhEHjQKBgQDw4rQ6P3BIEE/PQd2u3HJvH8WqfHYdKQW6s4i1sSkLR2Je/my0H5m4o0LRtwG5xs3VPNcK2RdQAosIKtAcxVOm2u7qg0pZmbXYH5TfL/YsaPY72yM0qjda6xcZU4X1Yd6x9Xa08pgmBisRr/Uo2uNUpCn+RBOnPDjaSpXEfXffIwKBgHnXGxkoWQIOzun30uHpqx0QTEPDocsHtL7BFJi00aCSafVw2KIcLggUNHKtPRAHCMs2vmyjSLyNI0nUIsKxoQV7rFO7z3fX/WlkEh7szUpX/1WdiVEl7+EDP5BlmKUqS6uh5dJwUOUQfQgJwmSMSAaizEmA1iYrOYxtcn9gVS4tAoGBAMNXdMQPkeQ+phny1ezphDstTsR0bewzyhufX+vHoPsuhk12kXx4a9ZZPuSGPfYDjAOydMitR8Rwa4LSBTZvpuiWfkza7z498kMzSSy83ishax0bFi+tIXqvTmoRW36kQU2bOwp9+HhNZDvRr0PUTanj/tHdLvrdUVVkSpOvE7h1AoGAY6TqZi6YbNJ9sldm/VW+4icJ3J4i3SnWhTzX4f0wJ0yh7BrRNZ/00mYYG+VY1zfe/4p5kpbD5Qee7CrYsYu41/VX4z3qOlMXz8ht4E5zisqs+Z12LyCRe1te6hwiGGyx66Wg1ihM4Pntx3eGptcdWXVjde/dQNJCv4+F8TrCqLc=";
            std::string  publicKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAty7AgeBJSijIW8ZUjtOqIZ98JO0G5X3XrwvSZasO6i+bOMJO7N1bzcsii4LTKsHIauBLQvYC/rxMzIr1cjoH0vCE+bKN2cCZI3DK78uvNtvkJOOIQTSq+n2FboF4aBMbY1ygDdsRVjODO6jGxkb8w3ABYtnlnXuKVWPSmj2It9yhJDONbpi7Fl7/M6etBSq5Xl05YceoFfMLuGyxm0wjoyI0T0DO0npfc7FurWP+7S65rNKUVRvXrDafvx2++3XIyNtj5Wh95bjUuY4suZxs55naNfh7HhVUPESvQp6bHU6LeWo3LRPzQ+dov1KSeDJKXGBXdAfvbbFS3XDxNXLbRwIDAQAB";

            RSAPrivateKeySigner signer(privateKey, "base64");

            std::cout << "demoRsaSign() " << std::endl;

            std::cout << signer.signToBase64(plainText) << std::endl;

        }

        //https://docs.oracle.com/en/java/javase/19/docs/specs/security/standard-names.html
        // https://developer.android.com/reference/javax/crypto/Cipher
        void demoWithJava() {
            std::string privateKey = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAMmZq1YVbuxBh+tw2RzVAI+VgxECztkAT3FTxLI7WBxNFBwhg3b1O7ECjRc4D8Yhq8N7DijLE/1CZft9sLHch3rE2igYU+SFIxQvWIU+MsOaFmE1fPZlSDpJbXiFd8hHRjJaomaWqRvZtOkBePzSMEUxFRcUPJRBn/YbWDdCjY1PAgMBAAECgYAEUzWnzSHqE6XU2UDvK2qtqel77fF+GlGZ/tATes5zHPw3dkiZvr0fGQzp2JwOBh7nPLabDXBKWKhTcujdh/uoDttznpi7BoA9wXEHkOsmJF0+SnFhxJ0ydxpoEWk+tTDrFpwZ4/KR8Rp3s+XoakXpiP3zH3k0+9+Yzcnfsy9dYQJBANnDcDikuP+pB5RBsQt0jCuIlL5xIfesVhGacbgRhiWTRL45IS1GJXGDYTQbJhHiG5z0kijZkJMyDiFb2KnIRMcCQQDs/7CU+BHOcOYQNCRSS1ClpyuQ9fEycLmOssSPQRfPd+JofB21xmWIh1Lu8IknTRrZC73VHQN8EgQg061s4Ns5AkEAs8fwbDNCMIACK9oYKpbr6jz2YEvSeUGkRSA25npBP+BXjpxn0ZLp8s8+fuAzC+yaU3hu+p60B3H5zHyhYXpfnQJAfe6/3eiTTacgGKwcQL5UdDGILNcC+1J6xyCm4ZgtFskVPX/2KYjqmsmNf/nAZ2nJQlvC22M3Xs4T832HQbuZwQJAGdGMaGuQwBBfI+JgONsTDu5Bb9lqiQFOQhKWsx3XHUe50dpSDenjal6djopfRgTkeD2S9ern/GIRt7ndLKdMZg==";
            std::string publicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDJmatWFW7sQYfrcNkc1QCPlYMRAs7ZAE9xU8SyO1gcTRQcIYN29TuxAo0XOA/GIavDew4oyxP9QmX7fbCx3Id6xNooGFPkhSMUL1iFPjLDmhZhNXz2ZUg6SW14hXfIR0YyWqJmlqkb2bTpAXj80jBFMRUXFDyUQZ/2G1g3Qo2NTwIDAQAB";
            std::string plainText = "hello world rsa";

            {
                std::string encryptedTextBase64 = "WFXaYBv9LkBHWRWhksI8Buqp0SYmVmM0r96Jlcdy1P5R3v2X+LM4AtTOiK8Epu4y2agc8B60XxyBffAXkN4LyVMLfgTw4F/LNguBbt0wwhgKkNjbbiOEJp2w/6ZoHYPziQc0+GZW+QF9wzbQWD3SLZ+GZpguedw9U+mvRy64zE0=";
                RSAPrivateKeyDecryptor decryptor(privateKey, "base64");
                std::cout << RSA_PKCS1Padding << std::endl;
                std::cout << decryptor.decryptFromBase64(encryptedTextBase64) << std::endl;
            }

            {
                std::string encryptedTextBase64OAEPPadding = "C6wlojggahmokkp1ccjEDluNvJZoUyQ1zIMhM0cicccTQZLZDWKgrVxdKNtRY3oguBDXQZtCqaBhrL8vuUR3iYLvIuT3VJW5IuiMomadt43U21UdFoI8CZREhpSr5CBX9xZF3d6UGpLTRM0rYMWhz8KYKj+fPhoEvx6sZwUEaWI=";

                RSAPrivateKeyDecryptor decryptor(privateKey, "base64", RSA_OAEPPadding);
                std::cout << RSA_OAEPPadding << std::endl;
                std::cout << decryptor.decryptFromBase64(encryptedTextBase64OAEPPadding) << std::endl;
            }

        }



    }
}
