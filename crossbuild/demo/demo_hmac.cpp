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
            std::string result = "ti+NvaQtWG3u4+iNv/7MWgR48gACs+bWZ8iTUAUpJwQ=";
            std::cout << signer.signToBase64("test sign") << std::endl;
            int test_count = 10000*100;
            {
                auto start = std::chrono::high_resolution_clock::now();
                auto end = std::chrono::high_resolution_clock::now();
                auto used = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

                start = std::chrono::high_resolution_clock::now();
                std::string plainText = "hello world";
                for(int i=0; i<test_count; i++) {
                    signer.signToHex("test signtest signtest signtest signtest signtest sign");
                }
                end = std::chrono::high_resolution_clock::now();
                used = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
                std::cout << "Hmac times per second " <<  used.count() << std::endl;
            }
        }
    }
}
