//
// Created by efurture on 25-8-16.
//

#ifndef CAMEL_SALT_H
#define CAMEL_SALT_H
#include <string>
#include "openssl/types.h"


namespace camel {
    namespace crypto {
        std::string genSalt(size_t len);
        std::string genHexSalt(size_t len);
        std::string genBase64Salt(size_t len);
    }
}



#endif //COMMON_SALT_H
