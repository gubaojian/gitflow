//
// Created by baojian on 25-8-5.
//

#include "test_hex.h"
#include "../common/fast_hex.h"
#include <iostream>

namespace camel {
    namespace crypto {

        std::string test_hex_decode_by_bn(const std::string_view &input) {
            std::string result;
            BIGNUM *bn = BN_new();
            if (bn == nullptr) {
                return result;
            }
            if (BN_hex2bn(&bn, input.data()) == 0) {
                BN_free(bn);
                return result;
            }

            int expected_len = input.length()/2;
            result.resize(expected_len);
            unsigned char* out = (unsigned char*)(result.data());
            BN_bn2binpad(bn, out, expected_len);
            BN_free(bn);
            return result;
        }
        void testHex() {
            bool passed = true;
            {
                std::string input = "00a1";
                std::string output = hex_decode(input);
                passed = passed && (output.size() == 2);
            }

            {
                std::string hex = "30820122300D06092A864886F70D01010105000382010F003082010A0282010100CD567917CDEB40389FA3D2AA98A46FDB78A30C2C02BC6AD51CD17940C5790DB0D78E45E8317367B799A32D06E022985F51EE962205FFD95C8686D92DEB88E31A6295A6ED0DB77335AB60A2A3BA80518A1DF9D6823E9FFDF0E2B72EAFF0257744228945D0969DACC26F0A687132AEB561F6F5C06609263B5E4BA959BEF7CDEA7878157CA1FB24FEE367D8D6C4B376932CFD9DEFDFB28C17D6EB27898DF2F3D1A0A07BF6FB6BBC01F37A22EC3D1FA855CCE606ED7CCE7A43249A32040876CC9FEEBC1D9E9C945AA0663D1508CC01B01AC16C9BAF0DCE2B2735A172A3F37C1C64A4235F13EF704A24149B36635808095E3A1EBB2FA44E148759A4AB002C834622B70203010001";
                std::string expect_result = test_hex_decode_by_bn(hex);
                std::string result(hex.size()/2, '\0');
                decodeHexLUT4((uint8_t*)result.data(), (uint8_t*)hex.data(), hex.size()/2);
                passed = passed && (result == expect_result);
            }

            if (passed) {
                std::cout << "testHex() passed " << std::endl;
            } else {
                std::cout << "testHex() failed " << std::endl;
            }
        }
    }
}
