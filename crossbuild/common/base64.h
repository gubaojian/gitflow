//
// Created by baojian on 25-8-5.
//

#ifndef BASE64_H
#define BASE64_H
#include <string>

namespace camel {
    namespace crypto {
        /*
        * @brief 标准 Base64 编码（无换行符）
        * @param input 待编码的原始二进制数据
        * @return 编码后的 Base64 字符串（包含 +、/，可能包含 = 填充符，无换行）
        */
        std::string base64_encode(const std::string &input);

        /**
        * @brief URL 安全的 Base64 编码（无换行符，移除填充符）
        * @param input 待编码的原始二进制数据
        * @return 编码后的 URL 安全 Base64 字符串（+ 替换为 -，/ 替换为 _，无 = 填充符）
        */
        std::string base64_encode_url_safe(const std::string &input);

        /**
         * @brief 带换行的标准 Base64 编码（每 64 字符添加换行）pem格式key采用这种格式
         * @param input 待编码的原始二进制数据
         * @return 编码后的 Base64 字符串（包含 +、/、= 填充符，每 64 字符换行）
         */
        std::string base64_encode_new_line(const std::string &input);

        /**
         * @brief 通用 Base64 解码（兼容标准和 URL 安全格式）
         * @param input 待解码的 Base64 字符串（支持标准格式的 +、/、=，及 URL 安全的 -、_）
         * @return 解码后的原始二进制数据；解码失败返回空字符串
         */
        std::string base64_decode(const std::string &input);
        std::string base64_decode_url_safe(const std::string &input);
    }
}





#endif //BASE64_H
