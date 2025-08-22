//
// Created by efurture on 25-8-16.
//

#include "salt.h"
#include "config.h"
#include <unordered_map>
#include <memory>
#include <mutex>

#include "base64.h"
#include "hex.h"
#include "openssl/rand.h"

namespace camel {
    namespace crypto {
        std::string genSalt(size_t len) {
            std::string salt(len, '\0');
            unsigned char *buf = (unsigned char *)salt.data();
            RAND_bytes(buf, len);
            return salt;
        }
        std::string genHexSalt(size_t len) {
            return hex_encode(genSalt(len));
        }
        std::string genBase64Salt(size_t len) {
            return base64_encode(genSalt(len));
        }
    }
}
