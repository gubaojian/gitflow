//
// Created by baojian on 25-8-14.
//

#include "digest.h"

#include <iostream>

#include "base64.h"
#include "config.h"
#include "hex.h"
#include "openssl/evp.h"


namespace camel {
    namespace crypto {
        MessageDigest::MessageDigest(const std::string &algorithm) {
            this->algorithm = algorithm;
        }

        std::string MessageDigest::digest(const std::string_view& data) {
            OSSL_LIB_CTX *libctx = getOSSL_LIB_CTX();
            EVP_MD *md = EVP_MD_fetch(libctx, algorithm.data(), NULL);
            if (md == nullptr) {
                std::cerr << "MessageDigest::digest() Failed to EVP_MD_fetch " << algorithm << std::endl;
                printOpenSSLError();
                return "";
            }
            EVP_MD_CTX *ctx = EVP_MD_CTX_new();
            if (ctx == nullptr) {
                std::cerr << "MessageDigest::digest() Failed to EVP_MD_CTX_new() " << std::endl;
                printOpenSSLError();
                EVP_MD_free(md);
                return "";
            }

            if (EVP_DigestInit_ex2(ctx, md, NULL) != 1) {
                std::cerr << "MessageDigest::digest() Failed to EVP_DigestInit_ex2() " << std::endl;
                printOpenSSLError();
                EVP_MD_CTX_free(ctx);
                EVP_MD_free(md);
                return "";
            }

            if (EVP_DigestUpdate(ctx, data.data(), data.size()) != 1) {
                std::cerr << "MessageDigest::digest() Failed to EVP_DigestUpdate() " << std::endl;
                printOpenSSLError();
                EVP_MD_CTX_free(ctx);
                EVP_MD_free(md);
                return "";
            }
            std::string buffer(EVP_MAX_MD_SIZE, '\0');
            unsigned char *out = (unsigned char *) buffer.data();
            unsigned int outlen = buffer.size();
            if (EVP_DigestFinal_ex(ctx, out, &outlen) != 1) {
                std::cerr << "MessageDigest::digest() Failed to EVP_DigestFinal_ex() " << std::endl;
                printOpenSSLError();
                EVP_MD_CTX_free(ctx);
                EVP_MD_free(md);
                return "";
            }
            buffer.resize(outlen);
            EVP_MD_CTX_free(ctx);
            EVP_MD_free(md);
            return buffer;
        }


        std::string MessageDigest::digestToHex(const std::string_view& data) {
            return hex_encode_lower(digest(data));
        }

        std::string MessageDigest::digestToBase64(const std::string_view& data) {
            return base64_encode(digest(data));
        }


    }
}


namespace camel {
    namespace crypto {

        XOFMessageDigest::XOFMessageDigest(const std::string &algorithm, size_t hashLength) {
            this->algorithm = algorithm;
            this->hashLength = hashLength;
        }

        std::string XOFMessageDigest::digest(const std::string_view& data) {
            if (hashLength <= 0) {
                std::cerr << "XOFMessageDigest::digest() invalid hash length " << algorithm << algorithm << std::endl;
                return "";
            }
            OSSL_LIB_CTX *libctx = getOSSL_LIB_CTX();
            EVP_MD *md = EVP_MD_fetch(libctx, algorithm.data(), NULL);
            if (md == nullptr) {
                std::cerr << "XOFMessageDigest::digest() Failed to EVP_MD_fetch " << algorithm << std::endl;
                printOpenSSLError();
                return "";
            }
            EVP_MD_CTX *ctx = EVP_MD_CTX_new();
            if (ctx == nullptr) {
                std::cerr << "XOFMessageDigest::digest() Failed to EVP_MD_CTX_new() " << std::endl;
                printOpenSSLError();
                EVP_MD_free(md);
                return "";
            }

            if (EVP_DigestInit_ex2(ctx, md, NULL) != 1) {
                std::cerr << "XOFMessageDigest::digest() Failed to EVP_DigestInit_ex2() " << std::endl;
                printOpenSSLError();
                EVP_MD_CTX_free(ctx);
                EVP_MD_free(md);
                return "";
            }

            if (EVP_DigestUpdate(ctx, data.data(), data.size()) != 1) {
                std::cerr << "XOFMessageDigest::digest() Failed to EVP_DigestUpdate() " << std::endl;
                printOpenSSLError();
                EVP_MD_CTX_free(ctx);
                EVP_MD_free(md);
                return "";
            }
            std::string buffer(hashLength, '\0');
            unsigned char *out = (unsigned char *) buffer.data();
            unsigned int outlen = buffer.size();
            if (EVP_DigestFinalXOF(ctx, out, outlen) == 0) {
                std::cerr << "MessageDigest::digest() Failed to EVP_DigestFinalXOF() " << std::endl;
                printOpenSSLError();
                EVP_MD_CTX_free(ctx);
                EVP_MD_free(md);
                return "";
            }
            buffer.resize(outlen);
            EVP_MD_CTX_free(ctx);
            EVP_MD_free(md);
            return buffer;
        }


        std::string XOFMessageDigest::digestToHex(const std::string_view& data) {
            return hex_encode_lower(digest(data));
        }

        std::string XOFMessageDigest::digestToBase64(const std::string_view& data) {
            return base64_encode(digest(data));
        }


    }
}


namespace camel {
    namespace crypto {

                inline std::string digest(const std::string& algorithm, const std::string_view& data) {
                    MessageDigest digest(algorithm);
                    return digest.digest(data);
                }

                inline std::string digestToHex(const std::string& algorithm, const std::string_view& data) {
                    MessageDigest digest(algorithm);
                    return digest.digestToHex(data);
                }

                inline std::string digestToBase64(const std::string& algorithm, const std::string_view& data) {
                    MessageDigest digest(algorithm);
                    return digest.digestToBase64(data);
                }

             inline std::string xof_digest(const std::string& algorithm, const int hashLenth, const std::string_view& data) {
                    XOFMessageDigest digest(algorithm, hashLenth);
                    return digest.digest(data);
                }

               inline std::string xof_digestToHex(const std::string& algorithm, const int hashLenth, const std::string_view& data) {
                    XOFMessageDigest digest(algorithm, hashLenth);
                    return digest.digestToHex(data);
                }

                inline std::string xof_digestToBase64(const std::string& algorithm, const int hashLenth, const std::string_view& data) {
                    XOFMessageDigest digest(algorithm, hashLenth);
                    return digest.digestToBase64(data);
                }

                std::string md2(const std::string_view& data) {
                    return digest("MD2", data);
                }
                std::string md2ToHex(const std::string_view& data) {
                    return digestToHex("MD2", data);
                }
                std::string md2ToBase64(const std::string_view& data) {
                    return digestToBase64("MD2", data);
                }
                std::string md5(const std::string_view& data) {
                    return digest("MD5", data);
                }
                std::string md5ToHex(const std::string_view& data) {
                    return digestToHex("MD5", data);
                }
                std::string md5ToBase64(const std::string_view& data) {
                    return digestToBase64("MD5", data);
                }

                std::string md5Sha1(const std::string_view& data) {
                    return digest("MD5-SHA1", data);
                }
                std::string md5Sha1ToHex(const std::string_view& data) {
                    return digestToHex("MD5-SHA1", data);
                }
        
                std::string md5Sha1ToBase64(const std::string_view& data) {
                    return digestToBase64("MD5-SHA1", data);
                }

                std::string sha1(const std::string_view& data) {
                    return digest("SHA1", data);
                }
                std::string sha1ToHex(const std::string_view& data) {
                    return digestToHex("SHA1", data);
                }
                std::string sha1ToBase64(const std::string_view& data) {
                    return digestToBase64("SHA1", data);
                }
                std::string sha224(const std::string_view& data) {
                    return digest("SHA2-224", data);
                }
                std::string sha224ToHex(const std::string_view& data) {
                    return digestToHex("SHA2-224", data);
                }
                std::string sha224ToBase64(const std::string_view& data) {
                    return digestToBase64("SHA2-224", data);
                }
                std::string sha256(const std::string_view& data) {
                    return digest("SHA2-256", data);
                }
                std::string sha256ToHex(const std::string_view& data) {
                    return digestToHex("SHA2-256", data);
                }
                std::string sha256ToBase64(const std::string_view& data) {
                    return digestToBase64("SHA2-256", data);
                }
                std::string sha256_192(const std::string_view& data) {
                    return digest("SHA2-256/192", data);
                }
                std::string sha256_192ToHex(const std::string_view& data) {
                    return digestToHex("SHA2-256/192", data);
                }
                std::string sha256_192ToBase64(const std::string_view& data) {
                    return digestToBase64("SHA2-256/192", data);
                }
                std::string sha384(const std::string_view& data) {
                    return digest("SHA2-384", data);
                }
                std::string sha384ToHex(const std::string_view& data) {
                    return digestToHex("SHA2-384", data);
                }
                std::string sha384ToBase64(const std::string_view& data) {
                    return digestToBase64("SHA2-384", data);
                }
                std::string sha512(const std::string_view& data) {
                    return digest("SHA2-512", data);
                }
                std::string sha512ToHex(const std::string_view& data) {
                    return digestToHex("SHA2-512", data);
                }

                std::string sha512ToBase64(const std::string_view& data) {
                    return digestToBase64("SHA2-512", data);
                }

                std::string sha512_224(const std::string_view& data) {
                    return digest("SHA2-512/224", data);
                }

                std::string sha512_224ToHex(const std::string_view& data) {
                    return digestToHex("SHA2-512/224", data);
                }

                std::string sha512_224ToBase64(const std::string_view& data) {
                    return digestToBase64("SHA2-512/224", data);
                }

                std::string sha512_256(const std::string_view& data) {
                    return digest("SHA2-256/256", data);
                }
                std::string sha512_256ToHex(const std::string_view& data) {
                    return digestToHex("SHA2-256/256", data);
                }
                std::string sha512_256ToBase64(const std::string_view& data) {
                    return digestToBase64("SHA2-256/256", data);
                }
                std::string sha3_224(const std::string_view& data) {
                    return digest("SHA3-224", data);
                }
                std::string sha3_224ToHex(const std::string_view& data) {
                    return digestToHex("SHA3-224", data);
                }
                std::string sha3_224ToBase64(const std::string_view& data) {
                    return digestToBase64("SHA3-224", data);
                }
                std::string sha3_256(const std::string_view& data) {
                    return digest("SHA3-256", data);
                }
                std::string sha3_256ToHex(const std::string_view& data) {
                    return digestToHex("SHA3-256", data);
                }
                std::string sha3_256ToBase64(const std::string_view& data) {
                    return digestToBase64("SHA3-256", data);
                }
                std::string sha3_384(const std::string_view& data) {
                    return digest("SHA3-384", data);
                }
                std::string sha3_384ToHex(const std::string_view& data) {
                    return digestToHex("SHA3-384", data);
                }
                std::string sha3_384ToBase64(const std::string_view& data) {
                    return digestToBase64("SHA3-384", data);
                }
                std::string sha3_512(const std::string_view& data) {
                    return digest("SHA3-512", data);
                }
                std::string sha3_512ToHex(const std::string_view& data) {
                    return digestToHex("SHA3-512", data);
                }
                std::string sha3_512ToBase64(const std::string_view& data) {
                    return digestToBase64("SHA3-512", data);
                }

                std::string ripemd_160(const std::string_view& data) {
                    return digest("RIPEMD160", data);
                }
                std::string ripemd_160ToHex(const std::string_view& data) {
                    return digestToHex("RIPEMD160", data);
                }
                std::string ripemd_160ToBase64(const std::string_view& data) {
                    return digestToBase64("RIPEMD160", data);
                }

                std::string sm3(const std::string_view& data) {
                    return digest("SM3", data);
                }

                std::string sm3ToHex(const std::string_view& data) {
                    return digestToHex("SM3", data);
                }

                std::string sm3ToBase64(const std::string_view& data) {
                    return digestToBase64("SM3", data);
                }

                std::string shake128(const std::string_view& data, const size_t hashLength) {
                    return xof_digest("SHAKE128", hashLength, data);
                }

                std::string shake128ToHex(const std::string_view& data, const size_t hashLength) {
                    return xof_digestToHex("SHAKE128", hashLength, data);
                }

                std::string shake128ToBase64(const std::string_view& data, const size_t hashLength) {
                    return xof_digestToBase64("SHAKE128", hashLength, data);
                }

                std::string shake256(const std::string_view& data, const size_t hashLength) {
                    return xof_digest("SHA256", hashLength, data);
                }

                std::string shake256ToHex(const std::string_view& data, const size_t hashLength) {
                    return xof_digestToHex("SHA256", hashLength, data);
                }

                std::string shake256ToBase64(const std::string_view& data, const size_t hashLength) {
                    return xof_digestToBase64("SHA256", hashLength, data);
                }
    }
}
