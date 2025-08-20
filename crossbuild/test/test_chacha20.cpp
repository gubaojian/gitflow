//
// Created by baojian on 2025/8/20.
//

#include "test_chacha20.h"
#include "../common/chacha20.h"
#include "../common/file_utils.h"

#include <iostream>

namespace camel {
    namespace crypto {
        void testChaCha20KeyGen() {
            {
                ChaCha20KeyGenerator chacha20Key;
                {
                    std::cout <<"-------------- ChaCha20Key --------------" << std::endl;
                    std::cout << chacha20Key.getHexKey() << std::endl;
                    std::cout << chacha20Key.getBase64Key() << std::endl;
                }
                FileUtils::writeFile("chacha20_key.txt", chacha20Key.getBase64Key(), true);
            }
        }
        void testChaCha20KeyEncrypt() {

        }
    }
}
