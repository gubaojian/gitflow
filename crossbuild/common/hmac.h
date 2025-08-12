//
// Created by baojian on 25-8-12.
//

#ifndef HMAC_SIGN_H
#define HMAC_SIGN_H
#include <string>

#include "openssl/types.h"

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

        class HMACSha2_256FastSigner {
        public:
            explicit HMACSha2_256FastSigner(const std::string& secret);
            ~HMACSha2_256FastSigner();
            std::string sign(const std::string_view& data);
            std::string signToHex(const std::string_view& data);
            std::string signToBase64(const std::string_view& data);
            bool checkSign(const std::string_view& data, const std::string_view& sign);
            bool checkHexSign(const std::string_view& data, const std::string_view& sign);
            bool checkBase64Sign(const std::string_view& data, const std::string_view& sign);
        public:
            HMACSha2_256FastSigner(const HMACSha2_256FastSigner&) = delete;
            HMACSha2_256FastSigner& operator=(const HMACSha2_256FastSigner&) = delete;
            HMACSha2_256FastSigner(HMACSha2_256FastSigner&&) noexcept;
            HMACSha2_256FastSigner& operator=(HMACSha2_256FastSigner&&) noexcept;
        private:
            std::string secret;
            EVP_MAC* evpMac = nullptr; //复用context，速度比不复用快1倍左右。
            EVP_MAC_CTX* hmacCtx = nullptr; //复用context，速度比不复用快1倍左右。
        };




    }
}





#endif //HMAC_SIGN_H
