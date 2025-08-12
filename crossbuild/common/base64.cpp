//
// Created by baojian on 25-8-5.
//

#include "base64.h"
#include <ios>
#include <iostream>
#include <openssl/evp.h>
#include <openssl/types.h>

#include "config.h"

namespace camel {
    namespace crypto {
        std::string base64_encode(const std::string &input) {
            if (input.empty()) {
                return "";
            }
            BIO *bio, *b64;
            // Create a base64 filter BIO
            b64 = BIO_new(BIO_f_base64());
            BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

            bio = BIO_new(BIO_s_mem());

            BIO_push(b64, bio);
            BIO_write(b64, input.data(), input.length());

            BIO_flush(b64);
            char* output_data = nullptr;
            long output_len = BIO_get_mem_data(bio, &output_data); // 获取内存指针和长度
            std::string result(output_data, output_len);
            // Free all BIOs in the chain
            BIO_free_all(b64);
            return result;
        }

        std::string base64_encode_url_safe(const std::string &input) {
            std::string source = base64_encode(input);
            for (size_t i = 0; i < source.length(); ++i) {
                if (source[i] == '+') {
                    source[i] = '-';
                } else if (source[i] == '/') {
                    source[i] = '_';
                }
            }
            return source;
        }

        std::string base64_encode_new_line(const std::string &input) {
            if (input.empty()) {
                return "";
            }
            EVP_ENCODE_CTX *ctx = EVP_ENCODE_CTX_new(); // 创建编码上下文
            if (ctx == nullptr) return "";
            int ret = 0;
            int len = 0;
            int out_len = 0;

            std::string result;
            result.resize(input.length()*2);
            EVP_EncodeInit(ctx);

            unsigned char *out = (unsigned char*)result.data();;
            unsigned char *in = (unsigned char*)input.data();

            if (EVP_EncodeUpdate(ctx, out, &len, in, input.size()) != 1) {
                EVP_ENCODE_CTX_free(ctx);
                return "";
            }
            out_len = len;

            // 结束处理（补全Base64的=填充）
            int final_len = 0;
            EVP_EncodeFinal(ctx, out + len, &final_len);
            out_len += final_len;
            result.resize(out_len);
            EVP_ENCODE_CTX_free(ctx);
            return result;
        }

        std::string base64_decode_std(const std::string_view &input) {
            if (input.empty()) {
                return "";
            }
            std::string result;
            EVP_ENCODE_CTX *ctx = EVP_ENCODE_CTX_new();
            if (ctx == nullptr) {
                return result;
            }
            result.resize(input.length());
            EVP_DecodeInit(ctx);

            int out_len = 0;
            int len = 0;
            unsigned char *out = (unsigned char*)result.data();;
            unsigned char *in = (unsigned char*)input.data();
            if (EVP_DecodeUpdate(ctx, out, &len, in, input.size()) < 0) { // 负数表示解码错误
                EVP_ENCODE_CTX_free(ctx);
                return "";
            }
            out_len = len;

            // 结束处理（验证填充是否合法）
            int final_len = 0;
            int ret = EVP_DecodeFinal(ctx, out + len, &final_len);
            if (ret != 1) { // 1表示成功
                EVP_ENCODE_CTX_free(ctx);
                return "";
            }
            out_len += final_len;
            result.resize(out_len);
            EVP_ENCODE_CTX_free(ctx);
            return result;
        }

        std::string base64_decode_std(const std::string &input) {
            return base64_decode_std(std::string_view(input));
        }

        std::string base64_decode(const std::string &input) {
            return base64_decode_std(input);
        }
        std::string base64_decode_url_safe(const std::string &input) {
            return base64_decode_url_safe(std::string_view(input));
        }
        std::string base64_decode_url_safe(const std::string_view &input) {
            if (input.empty()) {
                return "";
            }
            bool needTransform = false;
            for (size_t i = 0; i < input.length(); ++i) {
                if (input[i] == '-' || input[i] == '_') {
                    needTransform = true;
                    break;
                }
            }
            if (needTransform) {
                std::string source(input);
                for (size_t i = 0; i < source.length(); ++i) {
                    if (source[i] == '-') {
                        source[i] = '+';
                    } else if (source[i] == '_') {
                        source[i] = '/';
                    }
                }
                return base64_decode_std(source);
            }
            return base64_decode_std(input);
        }

        void base64_padding(std::string &input) {
            size_t len = input.size();
            if (len % 4 != 0) {
                size_t pad = 4 - (len % 4);
                if (pad == 3) { // 非法情况：无法通过填充修复
                    return;
                }
                input.append(std::string(pad, '='));
            }
        }

        void base64_remove_padding(std::string &source) {
            while (!source.empty() && source[source.length() - 1] == '=') {
                source.resize(source.length() - 1);
            }
        }

    }
}
