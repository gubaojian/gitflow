//
// Created by baojian on 25-8-5.
//

#include "test_base64.h"


namespace camel {
    namespace crypto {
        void testBase64() {
            bool passed = true;
            {
                auto shortSource = "new line test";
                auto base64NoLine =  base64_encode(shortSource);
                auto base64NewLine =  base64_encode_new_line(shortSource);
                passed = passed && base64NoLine != base64NewLine;
                passed = passed && base64_decode(base64NoLine) == shortSource;
                passed = passed && base64_decode(base64NewLine) == shortSource;
            }
            {
                std::string longSource = "new line test";
                for (int i=0; i<512; i++) {
                    longSource.append(std::to_string(i));
                    longSource.append("_");
                    longSource.append("中文你好");
                }
                auto base64NoLine =  base64_encode(longSource);
                auto base64UrlSafe =  base64_encode_url_safe(longSource);
                auto base64NewLine =  base64_encode_new_line(longSource);
                passed = passed && base64NoLine.find('\n') == std::string::npos;
                passed = passed &&  base64NoLine.find('+') != std::string::npos;
                passed = passed && base64UrlSafe.find('=') != std::string::npos;
                passed = passed && base64UrlSafe.find('+') == std::string::npos;
                passed = passed && base64UrlSafe.find('/') == std::string::npos;
                passed = passed && base64NoLine != base64NewLine;
                passed = passed && base64_decode(base64NoLine) == longSource;
                passed = passed && base64_decode(base64NewLine) == longSource;
                passed = passed && base64_decode_url_safe(base64UrlSafe) == longSource;
            }
            if (passed) {
                std::cout << "testBase64() passed " << std::endl;
            } else {
                std::cout << "testBase64() failed " << std::endl;
            }
        }
    }
}
