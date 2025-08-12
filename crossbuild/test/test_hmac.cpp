//
// Created by baojian on 25-8-12.
//

#include "test_hmac.h"

#include <iostream>

#include "../common/base64.h"
#include "../common/hex.h"
#include "../common/hmac.h"

namespace camel {
    namespace crypto {
        void testHmac() {
            HMACSha2_256Signer signer("hello world");
            HMACSha2_256Signer fastSigner("hello world");
            std::string data = "test sign";
            std::string result = "ti+NvaQtWG3u4+iNv/7MWgR48gACs+bWZ8iTUAUpJwQ=";
            std::string result_plain = base64_decode(result);
            bool passed = true;
            {
                passed = passed && (signer.signToBase64(data)  == result );
                passed = passed && (signer.signToHex(data)  == hex_encode(result_plain));
                passed = passed && (signer.sign(data)  == result_plain);
            }
            {
                passed = passed && (signer.checkBase64Sign(data, signer.signToBase64(data)));
                passed = passed && (signer.checkHexSign(data, signer.signToHex(data)));
                passed = passed && (signer.checkSign(data, signer.sign(data)));
            }

            {
                passed = passed && (fastSigner.checkBase64Sign(data, signer.signToBase64(data)));
                passed = passed && (fastSigner.checkHexSign(data, signer.signToHex(data)));
                passed = passed && (fastSigner.checkSign(data, signer.sign(data)));
            }
            if (passed) {
                std::cout << "HMACSha2_256Signer testHmac() passed " << std::endl;
            } else {
                std::cout << "HMACSha2_256Signer testHmac() failed " << std::endl;
            }
        }
    }
}
