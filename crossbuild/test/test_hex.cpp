//
// Created by baojian on 25-8-5.
//

#include "test_hex.h"
#include <iostream>

namespace camel {
    namespace crypto {
        void testHex() {
            bool passed = true;
            {
                std::string input = "00a1";
                std::string output = hex_decode(input);
                passed = passed && (output.size() == 2);
            }

            if (passed) {
                std::cout << "testHex() passed " << std::endl;
            } else {
                std::cout << "testHex() failed " << std::endl;
            }
        }
    }
}
