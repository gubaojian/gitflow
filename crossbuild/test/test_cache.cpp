//
// Created by baojian on 2025/8/22.
//

#include "test_cache.h"

#include <mutex>
#include <unordered_map>

#include "openssl/evp.h"


namespace camel {
    namespace crypto {
        struct CacheItem {
            std::string algorithm;
            EVP_PKEY* evpKey;
        };

        std::unordered_map<std::string, CacheItem> evpKeyCacheMap;
        std::mutex evpKeyCacheMutex;

        EVP_PKEY* evpKeyCacheGetInner(const std::string& key, const std::string& algorithm) {
            EVP_PKEY* pkey = nullptr;
            if (evpKeyCacheMap.empty()) {
                return pkey;
            }
            auto it = evpKeyCacheMap.find(key);
            if (it != evpKeyCacheMap.end()) {
                if (it->second.algorithm == algorithm) {
                    pkey = it->second.evpKey;
                }
            }
            return pkey;
        }

        void evpKeyCacheClearAllInner() {
            for (auto cacheIt : evpKeyCacheMap) {
                if (cacheIt.second.evpKey != nullptr) {
                    EVP_PKEY_free(cacheIt.second.evpKey);
                }
            }
            evpKeyCacheMap.clear();
        }

        EVP_PKEY* evpKeyCacheGet(const std::string& key, const std::string& algorithm) {
            std::lock_guard<std::mutex> lock(evpKeyCacheMutex);
            EVP_PKEY* pkey =  evpKeyCacheGetInner(key, algorithm);
            if (pkey != nullptr) {
                EVP_PKEY_up_ref(pkey);
            }
            return pkey;
        }


        void evpKeyCachePut(const std::string& key, const std::string& algorithm, EVP_PKEY* evpKey) {
            if (evpKey == nullptr) {
                return;
            }
            std::lock_guard<std::mutex> lock(evpKeyCacheMutex);
            EVP_PKEY_up_ref(evpKey);
            if (evpKeyCacheMap.size() >= 12) {
                evpKeyCacheClearAllInner();
            }
            EVP_PKEY* cachedKey = evpKeyCacheGetInner(key, algorithm);
            if (cachedKey  != nullptr) {
                EVP_PKEY_free(cachedKey);
            }
            CacheItem cacheItem {algorithm, evpKey};
            evpKeyCacheMap[key] = cacheItem;
        }
        void evpKeyCacheClearKey(const std::string& key, const std::string& algorithm) {
            std::lock_guard<std::mutex> lock(evpKeyCacheMutex);
            EVP_PKEY*  cachedKey = evpKeyCacheGetInner(key, algorithm);
            if (cachedKey  != nullptr) {
                EVP_PKEY_free(cachedKey);
                evpKeyCacheMap.erase(key);
            }
        }

        void evpKeyCacheClearAll() {
            std::lock_guard<std::mutex> lock(evpKeyCacheMutex);
            evpKeyCacheClearAllInner();
        }

    }
}
