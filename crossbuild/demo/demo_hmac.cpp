//
// Created by baojian on 25-8-12.
//

#include "demo_hmac.h"

#include <iostream>

#include "../common/hex.h"
#include "../common/hmac.h"

namespace camel {
    namespace crypto {

        void demoHmac() {
            HMACSha2_256Signer signer("hello world");
            HMACSha2_256FastSigner fastSigner("hello world");
            std::string result = "ti+NvaQtWG3u4+iNv/7MWgR48gACs+bWZ8iTUAUpJwQ=";
            std::string data = "test sign";
            std::cout << signer.signToBase64(data) << std::endl;
            std::cout << fastSigner.signToBase64(data) << std::endl;
            std::cout << fastSigner.signToBase64(data) << std::endl;
        }

        void demoHmacPerf() {
             HMACSha2_256Signer signer("hello world");
            HMACSha2_256FastSigner fastSigner("hello world");
            std::string text_sign_data = "test signtest signtest signtest signtest signtest sign";
            int test_count = 10000*100;
            {
                auto start = std::chrono::high_resolution_clock::now();
                auto end = std::chrono::high_resolution_clock::now();
                auto used = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

                start = std::chrono::high_resolution_clock::now();
                for(int i=0; i<test_count; i++) {
                    signer.sign(text_sign_data);
                }
                end = std::chrono::high_resolution_clock::now();
                used = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
                std::cout << "Hmac fast normal sign used " <<  used.count() << std::endl;
            }

            {
                auto start = std::chrono::high_resolution_clock::now();
                auto end = std::chrono::high_resolution_clock::now();
                auto used = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
                start = std::chrono::high_resolution_clock::now();
                for(int i=0; i<test_count; i++) {
                    fastSigner.sign(text_sign_data);
                }
                end = std::chrono::high_resolution_clock::now();
                used = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
                std::cout << "Hmac fast sign used " <<  used.count() << std::endl;
            }

            {
                 auto start = std::chrono::high_resolution_clock::now();
                 auto end = std::chrono::high_resolution_clock::now();
                 auto used = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

                 start = std::chrono::high_resolution_clock::now();
                 for(int i=0; i<test_count; i++) {
                     signer.signToHex(text_sign_data);
                 }
                 end = std::chrono::high_resolution_clock::now();
                 used = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
                 std::cout << "Hmac fast normal hex sign used " <<  used.count() << std::endl;
                 std::cout << "Hmac fast sign hex " << signer.signToHex(text_sign_data) << std::endl;
            }

            {
                 auto start = std::chrono::high_resolution_clock::now();
                 auto end = std::chrono::high_resolution_clock::now();
                 auto used = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
                 start = std::chrono::high_resolution_clock::now();
                 for(int i=0; i<test_count; i++) {
                     fastSigner.signToHex(text_sign_data);
                 }
                 end = std::chrono::high_resolution_clock::now();
                 used = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
                 std::cout << "Hmac fast sign hex used " <<  used.count() << std::endl;
                 std::cout << "Hmac fast sign hex " << fastSigner.signToHex(text_sign_data) << std::endl;
            }

            {
                 auto start = std::chrono::high_resolution_clock::now();
                 auto end = std::chrono::high_resolution_clock::now();
                 auto used = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

                 start = std::chrono::high_resolution_clock::now();
                 for(int i=0; i<test_count; i++) {
                     signer.signToBase64(text_sign_data);
                 }
                 end = std::chrono::high_resolution_clock::now();
                 used = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
                 std::cout << "Hmac fast normal base64 sign used " <<  used.count() << std::endl;
                 std::cout << "Hmac fast sign base64 " << signer.signToBase64(text_sign_data) << std::endl;
            }

            {
                 auto start = std::chrono::high_resolution_clock::now();
                 auto end = std::chrono::high_resolution_clock::now();
                 auto used = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
                 start = std::chrono::high_resolution_clock::now();
                 for(int i=0; i<test_count; i++) {
                     fastSigner.signToBase64(text_sign_data);
                 }
                 end = std::chrono::high_resolution_clock::now();
                 used = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
                 std::cout << "Hmac fast sign base64 used " <<  used.count() << std::endl;
                 std::cout << "Hmac fast sign base64 " << fastSigner.signToBase64(text_sign_data) << std::endl;
            }
        }
    }
}
