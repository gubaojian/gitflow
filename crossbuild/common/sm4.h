//
// Created by baojian on 2025/8/21.
//

#ifndef CAMEL_SM4_H
#define CAMEL_SM4_H
#include <string>

namespace camel {
    namespace crypto {
        class SM4KeyGenerator {
        public:
            explicit SM4KeyGenerator(int keyBitLength=128); //128，sm4只支持128位
            ~SM4KeyGenerator() = default;
        public:
            std::string getKey();
            std::string getHexKey();
            std::string getBase64Key();
        private:
            std::string secretKey;
            int mKeyBitLength = 128;
        };
    }
}


/**
 *
基础模式是 SM4 算法最常用的应用形式，用于实现对明文的加密 / 解密，解决分组密码 “仅能处理固定 128 位分组” 的局限，适配任意长度的明文数据。
模式名称	英文全称	核心原理	特点与适用场景
ECB 模式	Electronic Codebook	电子密码本模式	1. 无初始化向量（IV），每个 128 位明文分组独立加密，相同明文分组输出相同密文；
2. 安全性最低（易被统计分析攻击），仅适用于短数据（如密钥加密），不推荐通用场景。
CBC 模式	Cipher Block Chaining	密码分组链接模式	1. 需引入随机初始化向量（IV），当前明文分组先与前一密文分组异或，再进行 SM4 加密；
2. 解决 ECB 的 “明文重复暴露” 问题，但加密需串行（依赖前一分组），解密需按顺序；
3. 适用场景：文件加密、数据存储（对安全性有基础要求，且可接受串行处理）。
CFB 模式	Cipher Feedback	密码反馈模式	1. 需 IV，将 SM4 转化为 “流密码”：先加密 IV 生成 “密钥流”，与明文分组异或得到密文，再将密文反馈用于下一轮密钥流生成；
2. 支持 “s 位 CFB”（如 8 位、128 位），可按字节 / 位处理数据，加密和解密流程一致（均用 SM4 加密算法）；
3. 适用场景：实时数据传输（如流媒体、串口通信），需按小块处理数据的场景。
OFB 模式	Output Feedback	输出反馈模式	1. 需 IV，与 CFB 类似但反馈逻辑不同：先加密 IV 生成密钥流，再将密钥流（而非密文） 反馈用于下一轮；
2. 密钥流与明文独立，加密 / 解密可并行处理，且错误仅影响当前分组（CFB 错误会扩散）；
3. 适用场景：低延迟传输（如卫星通信）、实时语音 / 视频加密（需抗错误扩散）。
CTR 模式	Counter	计数器模式	1. 无需 IV，需引入唯一计数器（Counter）：对 “计数器 + 初始值（Nonce）” 进行 SM4 加密生成密钥流，与明文异或得到密文；
2. 加密 / 解密完全并行（每个分组的密钥流独立生成），性能最优，且相同密钥下 Counter 不可重复；
3. 适用场景：高性能需求场景（如大数据加密、云计算存储、VPN 隧道）。
SM4 的核心支持模式以 “ECB/CBC/CFB/OFB/CTR” 为基础，结合 CMAC、GCM 等扩展模式，可覆盖从基础数据加密到高安全认证加密的各类场景。
 *
 */
namespace camel {
    namespace crypto {
        class SM4Encryptor {
        public:
            /**
            * https://developer.android.com/reference/javax/crypto/Cipher
            * 免使用 ECB，优先选择 CBC（需保证 IV 随机）、CTR、GCM
            * @param algorithm  SM4/GCM/NoPadding
            * 其它模式默认PKCS5Padding 如 SM4/CBC/PKCS5Padding SM4/ECB/PKCS5Padding
            * @param secret
            * @param format
            */
            explicit SM4Encryptor(const std::string& algorithm,
                              const std::string_view& secret,
                              const std::string& format    = "base64");
            ~SM4Encryptor() = default;
        public:
            std::string encrypt(const std::string_view& plainText) const;
            std::string encryptToBase64(const std::string_view& plainText) const;
            std::string encryptToHex(const std::string_view& plainText) const;
        public:
            std::string encryptWithAAD(const std::string_view& plainText, const std::string_view& aad) const;
            std::string encryptToBase64WithAAD(const std::string_view& plainText, const std::string_view& aad) const;
            std::string encryptToHexWithAAD(const std::string_view& plainText, const std::string_view& aad) const;
        private:
            std::string secretKey;
            std::string algorithm; //无需传入位数如：支持传入SM4-GCM 即可，长度根据秘钥自动计算。目前支持 128 未来支持256，
        };
    }
}


namespace camel {
    namespace crypto {

        class SM4Decryptor {
        public:
            /**
           * https://developer.android.com/reference/javax/crypto/Cipher
           * 免使用 ECB，优先选择 CBC（需保证 IV 随机）、CTR、GCM
           * @param algorithm  SM4/GCM/NoPadding
           * 其它模式默认PKCS5Padding 如 SM4/CBC/PKCS5Padding
           * @param secret
           * @param format
           */
            explicit SM4Decryptor(const std::string& algorithm,
                                  const std::string_view& secret,
                                  const std::string& format    = "base64"
            );
            ~SM4Decryptor() = default;
        public:
            std::string decrypt(const std::string_view& encryptedData) const;
            std::string decryptFromBase64(const std::string_view& base64EncryptedText) const;
            std::string decryptFromHex(const std::string_view& hexEncryptedText) const;
        public:
            std::string decryptWithAAD(const std::string_view& encryptedData, const std::string_view& aad) const;
            std::string decryptFromBase64WithAAD(const std::string_view& base64EncryptedText, const std::string_view& aad) const;
            std::string decryptFromHexWithAAD(const std::string_view& hexEncryptedText, const std::string_view& aad) const;
        private:
            std::string secretKey;
            std::string algorithm; //无需传入位数如：128 256，支持传入SM4-GCM 即可，长度根据秘钥自动计算。
        };
    }
}


#endif //CAMEL_SM4_H