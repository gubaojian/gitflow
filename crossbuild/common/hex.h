//
// Created by baojian on 25-8-5.
//

#ifndef CAMEL_HEX_H
#define CAMEL_HEX_H
#include <string>



namespace camel {
    namespace crypto {
        std::string hex_encode(const std::string &input);
        std::string hex_encode(const std::string_view &input);
        std::string hex_decode(const std::string &input);
        std::string hex_decode(const std::string_view &input);
    }
}



#endif //CAMEL_HEX_H
