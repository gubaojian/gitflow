//
// Created by efurture on 25-8-15.
//

#ifndef HMAC_SHA_256_SIGNER_H
#define HMAC_SHA_256_SIGNER_H
#include <string>


namespace camel {
    namespace crypto {
        class HMACSha2_256Signer {
        public:
            explicit HMACSha2_256Signer(const std::string& secret);
            std::string sign(const std::string_view& data);
            std::string signToHex(const std::string_view& data);
            std::string signToBase64(const std::string_view& data);
            bool checkSign(const std::string_view& data, const std::string_view& sign);
            bool checkHexSign(const std::string_view& data, const std::string_view& sign);
            bool checkBase64Sign(const std::string_view& data, const std::string_view& sign);
        private:
            std::string secret;
        };

    }
}




#endif //HMAC_SHA_256_SIGNER_H
