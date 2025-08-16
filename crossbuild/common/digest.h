//
// Created by baojian on 25-8-14.
//

#ifndef CAMEL_DIGEST_H
#define CAMEL_DIGEST_H
#include <string>



namespace camel {
    namespace crypto {

        class MessageDigest {
            public:
            /**
            *  *  Known DIGEST names (not a complete list)
            *  # define OSSL_DIGEST_NAME_MD5            "MD5"
            *  # define OSSL_DIGEST_NAME_MD5_SHA1       "MD5-SHA1"
            *  # define OSSL_DIGEST_NAME_SHA1           "SHA1"
            *  # define OSSL_DIGEST_NAME_SHA2_224       "SHA2-224"
            *  # define OSSL_DIGEST_NAME_SHA2_256       "SHA2-256"
            *  # define OSSL_DIGEST_NAME_SHA2_256_192   "SHA2-256/192"
            *  # define OSSL_DIGEST_NAME_SHA2_384       "SHA2-384"
            *  # define OSSL_DIGEST_NAME_SHA2_512       "SHA2-512"
            *  # define OSSL_DIGEST_NAME_SHA2_512_224   "SHA2-512/224"
            *  # define OSSL_DIGEST_NAME_SHA2_512_256   "SHA2-512/256"
            *  # define OSSL_DIGEST_NAME_RIPEMD160      "RIPEMD160"
            *  # define OSSL_DIGEST_NAME_SHA3_224       "SHA3-224"
            *  # define OSSL_DIGEST_NAME_SHA3_256       "SHA3-256"
            *  # define OSSL_DIGEST_NAME_SHA3_384       "SHA3-384"
            *  # define OSSL_DIGEST_NAME_SHA3_512       "SHA3-512"
            *  # define OSSL_DIGEST_NAME_SM3            "SM3"
             * @param algorithm
             */
            explicit MessageDigest(const std::string& algorithm);
            public:
                std::string digest(const std::string_view& data);
                std::string digestToHex(const std::string_view& data);
                std::string digestToBase64(const std::string_view& data);
            private:
                std::string algorithm; //MD5 SHA2-256
        };

        /**
         * Extendable-Output Function
         */
        class XOFMessageDigest {
        public:
            /**
            *  #define SN_shake128             "SHAKE128"
            *  #define SN_shake256             "SHAKE256"
            *  for openssl hashLength can be any value
             * @param algorithm
             * @param  hashLength  from 1-64,
             */
            explicit XOFMessageDigest(const std::string& algorithm, size_t hashLength);
        public:
            std::string digest(const std::string_view& data);
            std::string digestToHex(const std::string_view& data);
            std::string digestToBase64(const std::string_view& data);
        private:
            std::string algorithm; //SHAKE128 SHAKE256
            size_t hashLength;
        };

        namespace DigestUtils {
                std::string md2(const std::string_view& data);
                std::string md2ToHex(const std::string_view& data);
                std::string md2ToBase64(const std::string_view& data);
                std::string md5(const std::string_view& data);
                std::string md5ToHex(const std::string_view& data);
                std::string md5ToBase64(const std::string_view& data);
                std::string md5Sha1(const std::string_view& data);
                std::string md5Sha1ToHex(const std::string_view& data);
                std::string md5Sha1ToBase64(const std::string_view& data);
                std::string sha1(const std::string_view& data);
                std::string sha1ToHex(const std::string_view& data);
                std::string sha1ToBase64(const std::string_view& data);
                std::string sha224(const std::string_view& data);
                std::string sha224ToHex(const std::string_view& data);
                std::string sha224ToBase64(const std::string_view& data);
                std::string sha256(const std::string_view& data);
                std::string sha256ToHex(const std::string_view& data);
                std::string sha256ToBase64(const std::string_view& data);
                std::string sha256_192(const std::string_view& data);
                std::string sha256_192ToHex(const std::string_view& data);
                std::string sha256_192ToBase64(const std::string_view& data);
                std::string sha384(const std::string_view& data);
                std::string sha384ToHex(const std::string_view& data);
                std::string sha384ToBase64(const std::string_view& data);
                std::string sha512(const std::string_view& data);
                std::string sha512ToHex(const std::string_view& data);
                std::string sha512ToBase64(const std::string_view& data);
                std::string sha512_224(const std::string_view& data);
                std::string sha512_224ToHex(const std::string_view& data);
                std::string sha512_224ToBase64(const std::string_view& data);
                std::string sha512_256(const std::string_view& data);
                std::string sha512_256ToHex(const std::string_view& data);
                std::string sha512_256ToBase64(const std::string_view& data);
                std::string sha3_224(const std::string_view& data);
                std::string sha3_224ToHex(const std::string_view& data);
                std::string sha3_224ToBase64(const std::string_view& data);
                std::string sha3_256(const std::string_view& data);
                std::string sha3_256ToHex(const std::string_view& data);
                std::string sha3_256ToBase64(const std::string_view& data);
                std::string sha3_384(const std::string_view& data);
                std::string sha3_384ToHex(const std::string_view& data);
                std::string sha3_384ToBase64(const std::string_view& data);
                std::string sha3_512(const std::string_view& data);
                std::string sha3_512ToHex(const std::string_view& data);
                std::string sha3_512ToBase64(const std::string_view& data);

                std::string ripemd_160(const std::string_view& data);
                std::string ripemd_160ToHex(const std::string_view& data);
                std::string ripemd_160ToBase64(const std::string_view& data);

                std::string sm3(const std::string_view& data);
                std::string sm3ToHex(const std::string_view& data);
                std::string sm3ToBase64(const std::string_view& data);

                std::string shake128(const std::string_view& data, const size_t hashLength);
                std::string shake128ToHex(const std::string_view& data, const size_t hashLength);
                std::string shake128ToBase64(const std::string_view& data, const size_t hashLength);

                std::string shake256(const std::string_view& data, const size_t hashLength);
                std::string shake256ToHex(const std::string_view& data, const size_t hashLength);
                std::string shake256ToBase64(const std::string_view& data, const size_t hashLength);

        };
    }
}





#endif //CAMEL_DIGEST_UTIL_H
