//
// Created by efurture on 25-8-16.
//

#ifndef CAMEL_COMMON_H
#define CAMEL_COMMON_H
#include <string>
#include "openssl/types.h"


namespace camel {
    namespace crypto {
        /**
         * 从缓存获取 EVP_PKEY 对象
         * @param key 密钥原始内容（如 PEM 字符串）
         * @param algorithm 算法类型（如 "RSA", "EC"）
         * @return 缓存的 EVP_PKEY*（成功）；nullptr（未命中）
         * @note 1. 线程安全；2. 调用者需通过 EVP_PKEY_free 释放
         */
        EVP_PKEY* evpKeyCacheGet(const std::string& key, const std::string& algorithm);
        void evpKeyCachePut(const std::string& key, const std::string& algorithm, EVP_PKEY* evpKey);
        void evpKeyCacheClearKey(const std::string& key, const std::string& algorithm);
        void evpKeyCacheClearAll();

    }
}



#endif //COMMON_H
