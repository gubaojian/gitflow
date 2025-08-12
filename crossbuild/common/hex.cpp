//
// Created by baojian on 25-8-5.
//

#include "hex.h"
#include "fast_hex.h"
#include <iostream>
#include <string>

#include <openssl/bn.h>

namespace camel {
    namespace crypto {
        inline std::string hex_encode_by_bn(const std::string &input) {
            std::string result;
            BIGNUM *bn = BN_new();
            if (bn == nullptr) {
                return result;
            }
            result.reserve(input.size() * 2 + 4);
            BN_bin2bn((unsigned char*)input.data(), input.length(), bn);
            char *hex = BN_bn2hex(bn);
            if (hex != nullptr) {
                result.append(hex);
                OPENSSL_free(hex);
            }
            BN_free(bn);
            return result;
        }
        //static constexpr char kEncoding[] = "0123456789abcdef";

        static constexpr char kEncoding[] = "0123456789ABCDEF";

        inline std::string hex_encode_by_block(const std::string_view& input) {
            const size_t input_len = input.size();
            if (input_len == 0) {
                return "";
            }
            std::string result(input.size() * 2, '\0');
            char* out = result.data();  // 直接操作缓冲区指针
            const uint8_t* in = (const uint8_t*)(input.data());

            // 批量处理：每次处理4字节（生成8个十六进制字符），减少循环次数
            size_t i = 0;
            const size_t can_batch_length = input_len - (input_len % 4);  // 4的倍数部分
            for (; i < can_batch_length; i += 4) {
                uint8_t b0 = in[i], b1 = in[i+1], b2 = in[i+2], b3 = in[i+3];
                out[0] = kEncoding[b0 >> 4];
                out[1] = kEncoding[b0 & 0xF];
                out[2] = kEncoding[b1 >> 4];
                out[3] = kEncoding[b1 & 0xF];
                out[4] = kEncoding[b2 >> 4];
                out[5] = kEncoding[b2 & 0xF];
                out[6] = kEncoding[b3 >> 4];
                out[7] = kEncoding[b3 & 0xF];
                out += 8;
            }

            // 处理剩余字节（不足4字节的部分）
            for (; i < input_len; ++i) {
                uint8_t b = in[i];
                *out++ = kEncoding[b >> 4];
                *out++ = kEncoding[b & 0xF];
            }
            return result;
        }

        inline std::string hex_encode_by_block2(const std::string_view& input) {
            std::string result(input.size() * 2, '\0');
            encodeHex((uint8_t*)result.data(), (const uint8_t*)input.data(), input.size());
            return result;
        }

        std::string hex_decode_by_bn(const std::string_view &input) {
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


        inline std::string hex_decode_by_block(const std::string_view &input) {
            if (input.size() % 2 != 0) {
                return "";
            }
            std::string result(input.size()/2, '\0'); // 预分配并初始化
            uint8_t* out = (uint8_t*)result.data();
            uint8_t* in = (uint8_t*)input.data();
            decodeHexLUT4(out, in, input.size()/2);
            return result;
        }


        std::string hex_encode(const std::string &input) {
            return hex_encode_by_block(input);
        }

        std::string hex_encode(const std::string_view &input) {
            return hex_encode_by_block(input);
        }

        std::string hex_decode(const std::string &input) {
            return hex_decode(std::string_view(input));
        }

        std::string hex_decode(const std::string_view &input) {
            return hex_decode_by_block(input);
        }
    }
}

