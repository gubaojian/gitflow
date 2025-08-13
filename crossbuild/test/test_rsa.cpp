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

        //https://docs.oracle.com/en/java/javase/19/docs/specs/security/standard-names.html
        // https://developer.android.com/reference/javax/crypto/Cipher
        // https://github.com/bcgit/bc-java/blob/d85840365a973e5cb2520eba5aba91f4458d47cb/prov/src/main/java/org/bouncycastle/jcajce/provider/asymmetric/rsa/CipherSpi.java#L234
        // bouncycastle和jdk实现有些不一致，
        void testRsaWithJava() {
            bool passed = true;
            std::string privateKey = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC3LsCB4ElKKMhbxlSO06ohn3wk7QblfdevC9Jlqw7qL5s4wk7s3VvNyyKLgtMqwchq4EtC9gL+vEzMivVyOgfS8IT5so3ZwJkjcMrvy6822+Qk44hBNKr6fYVugXhoExtjXKAN2xFWM4M7qMbGRvzDcAFi2eWde4pVY9KaPYi33KEkM41umLsWXv8zp60FKrleXTlhx6gV8wu4bLGbTCOjIjRPQM7Sel9zsW6tY/7tLrms0pRVG9esNp+/Hb77dcjI22PlaH3luNS5jiy5nGznmdo1+HseFVQ8RK9CnpsdTot5ajctE/ND52i/UpJ4MkpcYFd0B+9tsVLdcPE1cttHAgMBAAECggEABi7JyJhtYNdni9Fx4TA7uc7MPeLSLMTGlt3rSAsyAa2Bq7TDPTNredK1Y8gSoIrR3OmdILF1AGwSm4TFLAnRYclEc7kXGJZrlMqlztotG8joNmaHnsvMSZAbBNPR4JFkh0IFFPKj7yjl8QmNS/vxZBdPtKpuGZal4KPx48rX5ny5MBxjtaFW+eBK9Dla+1EqiuFHOU1uIibbNHDouS8g5wDFmRwFL+nrWgv9xSGj7BPfkFi0mpfGN6rTZeJQBlgzLCx4BRxcD8P62hOW0/sMiKORnSvDtWu9e6lA9qAidmzG8QyHkwz/u+BFFdbPB/PQUVw8uzVTJzvcwASumCRxYQKBgQDCrS1oPsazdixBedrADHbNP4njxrCCLZ9jJ5jazepgVCYSNGcM0YjHr6PfCAseEKT8BXpFDVVy5UR3jhZS+XasTVQl34cXUgZjIkFqSgLHPkeyo1p/QXi4HQNjBpQfpjrq5TpDyBLbfZ6Z8NLlXCtIcrVpdDrWP3jvj3MtFhEHjQKBgQDw4rQ6P3BIEE/PQd2u3HJvH8WqfHYdKQW6s4i1sSkLR2Je/my0H5m4o0LRtwG5xs3VPNcK2RdQAosIKtAcxVOm2u7qg0pZmbXYH5TfL/YsaPY72yM0qjda6xcZU4X1Yd6x9Xa08pgmBisRr/Uo2uNUpCn+RBOnPDjaSpXEfXffIwKBgHnXGxkoWQIOzun30uHpqx0QTEPDocsHtL7BFJi00aCSafVw2KIcLggUNHKtPRAHCMs2vmyjSLyNI0nUIsKxoQV7rFO7z3fX/WlkEh7szUpX/1WdiVEl7+EDP5BlmKUqS6uh5dJwUOUQfQgJwmSMSAaizEmA1iYrOYxtcn9gVS4tAoGBAMNXdMQPkeQ+phny1ezphDstTsR0bewzyhufX+vHoPsuhk12kXx4a9ZZPuSGPfYDjAOydMitR8Rwa4LSBTZvpuiWfkza7z498kMzSSy83ishax0bFi+tIXqvTmoRW36kQU2bOwp9+HhNZDvRr0PUTanj/tHdLvrdUVVkSpOvE7h1AoGAY6TqZi6YbNJ9sldm/VW+4icJ3J4i3SnWhTzX4f0wJ0yh7BrRNZ/00mYYG+VY1zfe/4p5kpbD5Qee7CrYsYu41/VX4z3qOlMXz8ht4E5zisqs+Z12LyCRe1te6hwiGGyx66Wg1ihM4Pntx3eGptcdWXVjde/dQNJCv4+F8TrCqLc=";

            std::string publicKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAty7AgeBJSijIW8ZUjtOqIZ98JO0G5X3XrwvSZasO6i+bOMJO7N1bzcsii4LTKsHIauBLQvYC/rxMzIr1cjoH0vCE+bKN2cCZI3DK78uvNtvkJOOIQTSq+n2FboF4aBMbY1ygDdsRVjODO6jGxkb8w3ABYtnlnXuKVWPSmj2It9yhJDONbpi7Fl7/M6etBSq5Xl05YceoFfMLuGyxm0wjoyI0T0DO0npfc7FurWP+7S65rNKUVRvXrDafvx2++3XIyNtj5Wh95bjUuY4suZxs55naNfh7HhVUPESvQp6bHU6LeWo3LRPzQ+dov1KSeDJKXGBXdAfvbbFS3XDxNXLbRwIDAQAB";
            std::string plainText = "hello world rsa";
            {
                std::string encryptedTextBase64 = "jxMNuI04koQoen/uy9treHY3JiwU/AISP0+yk/o+CRVCF1yXW8adif8KqJUpMTovOj++I7xwdZBKmNRw7ouk5yCMI81EKf72/CG9jCabJ02ow5EkVliSsHsMGQPrZH8hLuZdV/dqBBWzCJLkuTL/RYDznMRU11bo43nPud5/5wklJv3Y347FtIHU9OwcW62eEjU1BFWMF3LRRCXIWkwrN5atiGLWt/JrH8GgUfAnDWsZASJEa3LQY0lQEMbvaNonZadjfZJbn7kR5bDdvDawinMzA/hjyVk1IkW52vAppbRaGilIg4OCi8AE2XHsHtVJcQEG6kaoC34/8h3WQ7+ePQ==";
                RSAPrivateKeyDecryptor decryptor(privateKey, "base64");
                passed = passed && plainText == decryptor.decryptFromBase64(encryptedTextBase64);
            }

            {
                std::string encryptedTextBase64OAEPPadding = "ZIoFsDfrh/B2lC6IRVB0yXwnys4FJr+bF2mC04KURjEB5uCb50x8vz/NYPZwSz4CWRBoMefJxO1sbHVgt9S9CHMnlBavyHARv3gZtJ65rqbetJFv8rtHg909AybuatagOrfqzWNQt2mUcWh/61yiKP/WIs8ZvRA6LML+wgctivIlMuDxYdZTEhnF7Vp7D7XRUwDQ+/mm+4XF/1fjHep9fob5ZZsPs70lmgE7hqLVC9n97753Xwf7ToliPCY/TicjAy/IpRgJ5tcswf16doDxoYQfa87OKCV5BObQvxwt/qIz1EnOEMpW16xdJKLC0gz8d5vcCHJxJOwzzXw3BqLyEA==";
                RSAPrivateKeyDecryptor decryptor(privateKey, "base64", RSA_OAEPPadding);
                passed = passed && plainText ==  decryptor.decryptFromBase64(encryptedTextBase64OAEPPadding);
            }

            {
                std::string encryptedTextBase64OAEPPadding = "jA3Nc9x8G2wEJjRlnUXB+tgIv629f/EEpE85GXiFRW0anKNTyEk787agfnCLQJORLWOjNN78nUun4T/TnNP0Cao5fib9X/ehmYQB2hozJiL+GxmNuSnPgrBM4CGwgAz4ZTmJFqItnkzDCp1rrsPRSXu1yc+wqM2NtzHJvQMISBE7SbOLKmb7QL2hT8XOz88gu2GC3492cK51NrAl6FnvMUJY92/IwabUK7OfLJ7wo8ECy0bxBp45t6xqFi04a2aRy1kdRTZE1o1v13oEqebdj25PB+dz8t9YcE8gFs/1O0iKOR76e135jjSlqlHCVZLzqZ1m8ZKeDBav5BQK1dU7Fw==";
                RSAPrivateKeyDecryptor decryptor(privateKey, "base64", RSA_OAEPwithSHA_256andMGF1Padding);
                passed = passed && plainText ==  decryptor.decryptFromBase64(encryptedTextBase64OAEPPadding);
            }

            {
                std::string encryptedTextBase64OAEPPadding = "BawjLtIaV4ZSVncZajV4iP7PXzpHq+26RfCFT4CMTidF9yJ0UmVNbC8RRyy58Wn5ynVfhDi7PICIgChYHilFhxu2YldTdSgJbiVVT/hL2FLg0De5GWlSZc9FoZWBwTZSFUZ7dqHBD7AwcJKZhpaEdUh81rLqEzB198BSmrgdLJ1lPlywzu95oE/C1kiZVdQPRNAHvGsv/cfrr321uFMkVQ+STGg46k7560t/GZ0MWxSEIinWobbA93pbuyW4TCF3VOMlMTX33TfwZXkUQbthief5mFmUtUN+UFmeKBDCa5ScjcmQHNm0fxdfpM663p+HIuu+ipeC9AD1lCd418/mMA==";
                RSAPrivateKeyDecryptor decryptor(privateKey, "base64", RSA_OAEPwithSHA_512andMGF1Padding);
                passed = passed && plainText ==  decryptor.decryptFromBase64(encryptedTextBase64OAEPPadding);
            }

            {
                std::string encryptedTextBase64OAEPPadding = "KZAuxihuMpUgwZqyzNMj5DESbow+UpaEjl8TLu/lHnW3lamGTmZ9NmkVJ44G7UibWD0VIa9diT0vXwadLwgVaVwv7zQ2cUz7DVv9LeybfgZfC+NSIcnSi8sG4hMrVZq0kLbHDdfFt8qgq894sRGNdVpkp/HedwlbA87FQKTda4znG7pfDPN8hUR3kdXfiFep2DFxhyUcQzFMuJgHhNWvOjjpr2zUF3ZvHLrlvx3ahkgrj9Rm4ZgRJiTZCBuYWe8ndQ7iqjhDIU0scZTzKQizT28Anl8hVBouWYHqP4Ee/CcqwVJq8W1Xa7YedHR4tEuNVVoNAgol38P+CDylxNzzuQ==";
                RSAPrivateKeyDecryptor decryptor(privateKey, "base64", RSA_OAEP_SHA3_256_MGF1_SHA3_256);
                passed = passed && plainText ==  decryptor.decryptFromBase64(encryptedTextBase64OAEPPadding);
            }



            if (passed) {
                std::cout << "testRsaWithJava() passed " << std::endl;
            } else {
                std::cout << "testRsaWithJava() failed " << std::endl;
            }
        }

        void testRsaSign() {
            bool passed = true;
            {
                 std::string  plainText = "hello world rsa";
                 std::string  privateKey = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC3LsCB4ElKKMhbxlSO06ohn3wk7QblfdevC9Jlqw7qL5s4wk7s3VvNyyKLgtMqwchq4EtC9gL+vEzMivVyOgfS8IT5so3ZwJkjcMrvy6822+Qk44hBNKr6fYVugXhoExtjXKAN2xFWM4M7qMbGRvzDcAFi2eWde4pVY9KaPYi33KEkM41umLsWXv8zp60FKrleXTlhx6gV8wu4bLGbTCOjIjRPQM7Sel9zsW6tY/7tLrms0pRVG9esNp+/Hb77dcjI22PlaH3luNS5jiy5nGznmdo1+HseFVQ8RK9CnpsdTot5ajctE/ND52i/UpJ4MkpcYFd0B+9tsVLdcPE1cttHAgMBAAECggEABi7JyJhtYNdni9Fx4TA7uc7MPeLSLMTGlt3rSAsyAa2Bq7TDPTNredK1Y8gSoIrR3OmdILF1AGwSm4TFLAnRYclEc7kXGJZrlMqlztotG8joNmaHnsvMSZAbBNPR4JFkh0IFFPKj7yjl8QmNS/vxZBdPtKpuGZal4KPx48rX5ny5MBxjtaFW+eBK9Dla+1EqiuFHOU1uIibbNHDouS8g5wDFmRwFL+nrWgv9xSGj7BPfkFi0mpfGN6rTZeJQBlgzLCx4BRxcD8P62hOW0/sMiKORnSvDtWu9e6lA9qAidmzG8QyHkwz/u+BFFdbPB/PQUVw8uzVTJzvcwASumCRxYQKBgQDCrS1oPsazdixBedrADHbNP4njxrCCLZ9jJ5jazepgVCYSNGcM0YjHr6PfCAseEKT8BXpFDVVy5UR3jhZS+XasTVQl34cXUgZjIkFqSgLHPkeyo1p/QXi4HQNjBpQfpjrq5TpDyBLbfZ6Z8NLlXCtIcrVpdDrWP3jvj3MtFhEHjQKBgQDw4rQ6P3BIEE/PQd2u3HJvH8WqfHYdKQW6s4i1sSkLR2Je/my0H5m4o0LRtwG5xs3VPNcK2RdQAosIKtAcxVOm2u7qg0pZmbXYH5TfL/YsaPY72yM0qjda6xcZU4X1Yd6x9Xa08pgmBisRr/Uo2uNUpCn+RBOnPDjaSpXEfXffIwKBgHnXGxkoWQIOzun30uHpqx0QTEPDocsHtL7BFJi00aCSafVw2KIcLggUNHKtPRAHCMs2vmyjSLyNI0nUIsKxoQV7rFO7z3fX/WlkEh7szUpX/1WdiVEl7+EDP5BlmKUqS6uh5dJwUOUQfQgJwmSMSAaizEmA1iYrOYxtcn9gVS4tAoGBAMNXdMQPkeQ+phny1ezphDstTsR0bewzyhufX+vHoPsuhk12kXx4a9ZZPuSGPfYDjAOydMitR8Rwa4LSBTZvpuiWfkza7z498kMzSSy83ishax0bFi+tIXqvTmoRW36kQU2bOwp9+HhNZDvRr0PUTanj/tHdLvrdUVVkSpOvE7h1AoGAY6TqZi6YbNJ9sldm/VW+4icJ3J4i3SnWhTzX4f0wJ0yh7BrRNZ/00mYYG+VY1zfe/4p5kpbD5Qee7CrYsYu41/VX4z3qOlMXz8ht4E5zisqs+Z12LyCRe1te6hwiGGyx66Wg1ihM4Pntx3eGptcdWXVjde/dQNJCv4+F8TrCqLc=";
                 std::string  publicKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAty7AgeBJSijIW8ZUjtOqIZ98JO0G5X3XrwvSZasO6i+bOMJO7N1bzcsii4LTKsHIauBLQvYC/rxMzIr1cjoH0vCE+bKN2cCZI3DK78uvNtvkJOOIQTSq+n2FboF4aBMbY1ygDdsRVjODO6jGxkb8w3ABYtnlnXuKVWPSmj2It9yhJDONbpi7Fl7/M6etBSq5Xl05YceoFfMLuGyxm0wjoyI0T0DO0npfc7FurWP+7S65rNKUVRvXrDafvx2++3XIyNtj5Wh95bjUuY4suZxs55naNfh7HhVUPESvQp6bHU6LeWo3LRPzQ+dov1KSeDJKXGBXdAfvbbFS3XDxNXLbRwIDAQAB";

                {
                     std::string sign = "jg5r5z1SHWhfbzCa0TT8xblGCgP/HWMHs65UmsMw4Teqb6wwpfMdCaSUN2GhFRlKvssLg4kWM/+4uyCf7UhWsb1n++RDCdlyNu0dK3AXgD/kIrrkEkxx6FX7EK9Tf4C93232dERoGmPVySO7M6FNw3hCnkTTMya1/98Zzf4dxd/C5hCgiDI9yQUrMIpFCj0bKBFMRYcVavARPDe+o7B+X8e1lWqBECLHYdfBJpHW5VA+NGNlDYjFTX24hX8yP9EUUKyyzVRrMh+CttAtKR/p4LI3e2xCYYQqAdIW5b032E23l0N2F2obZcgI3y5wqveL5WKr5S+VSgS3WAvIHsqe9w==";
                     RSAPrivateKeySigner signer(privateKey, "base64");
                     RSAPublicKeyVerifier verifier(publicKey, "base64");

                     passed = passed && sign == signer.signToBase64(plainText);

                     passed = passed && verifier.verifyBase64Sign(sign, plainText);
                 }

                {
                     std::string sign = "M2u6EUrid/MUlAEa48PtvqPAml/PNJKGwVjXW4jVvr4PRP8uZoylM8mKiYjG1bc4b9T8Xe3n8Zpgd1pjuJrs2auNMtN3fPN8VD2yZG1L32KAj4RECgIaXXnGDvWMESrhTsbBc3LpWGihp0tTyqrnwk8TrdlByBFMSMp9KQxWMT+BzPwpc/G431w4g9iQa8qVrnX5HV4MuRMdJHadh1fKijs+0G7H0pmXFP/vQlwHtTJZ85QMN0IAs/OM/0QKLoOFHgfNt7mzdzutdQYfh+ixL+j8uj9JpuN7wr2pfnDOLklG9xiD+AP3RyR9yr/c/vjyLioJwJ1hjUNv+0CC3D70hg==";

                     RSAPrivateKeySigner signer(privateKey, "base64", "SHA1withRSA");
                     RSAPublicKeyVerifier verifier(publicKey, "base64", "SHA1withRSA");

                     passed = passed && sign == signer.signToBase64(plainText);

                     passed = passed && verifier.verifyBase64Sign(sign, plainText);
                }


            }
            if (passed) {
                std::cout << "testRsaSign() passed " << std::endl;
            } else {
                std::cout << "testRsaSign() failed " << std::endl;
            }
        }




    }
}
