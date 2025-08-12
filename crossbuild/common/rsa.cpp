//
// Created by baojian on 25-8-5.
//

#include "rsa.h"
#include <iostream>
#include <openssl/rsa.h>

#include "base64.h"
#include "hex.h"


namespace camel {
    namespace crypto {
        EVP_PKEY* RSAPublicKeyFromPem(const std::string& pemKey) {
            EVP_PKEY* key = nullptr;
            BIO* bio = BIO_new_mem_buf(pemKey.data(), static_cast<int>(pemKey.size()));
            if (!bio) {
                std::cerr << "RSAPublicKeyFromPem Failed to create memory BIO" << std::endl;
                printOpenSSLError();
                return key;
            }

            if (!PEM_read_bio_PUBKEY(bio, &key, nullptr, nullptr)) {
                std::cerr << "RSAPublicKeyFromPem Failed to PEM_read_bio_PUBKEY " << std::endl;
                printOpenSSLError();
                BIO_free(bio);
                return key;
            }
            BIO_free(bio);
            return key;
        }

        EVP_PKEY* RSAPublicKeyFromBase64(const std::string& base64Key) {
            return RSAPublicKeyFromDer(base64_decode_url_safe(base64Key));
        }

        EVP_PKEY* RSAPublicKeyFromHex(const std::string& hexKey) {
            return  RSAPublicKeyFromDer(hex_decode(hexKey));
        }

        EVP_PKEY* RSAPublicKeyFromDer(const std::string& derKey) {
            EVP_PKEY* key = nullptr;
            const unsigned char *in = (const unsigned char *)derKey.data();
            long length = derKey.size();
            if (d2i_PUBKEY(&key, &in, length) == nullptr) {
                std::cerr << "RSAPublicKeyFromDer Failed to d2i_PUBKEY " << std::endl;
                printOpenSSLError();
                return nullptr;
            }
            return key;
        }

        EVP_PKEY* RSAPublicKeyFromDerByBio(const std::string& derKey) {
            EVP_PKEY* key = nullptr;
            BIO* bio = BIO_new_mem_buf(derKey.data(), static_cast<int>(derKey.size()));
            if (!bio) {
                std::cerr << "RSAPublicKeyFromDer Failed to create memory BIO" << std::endl;
                printOpenSSLError();
                return key;
            }
            if (d2i_PUBKEY_bio(bio, &key) == nullptr) {
                std::cerr << "RSAPublicKeyFromDer Failed to d2i_PUBKEY_bio " << std::endl;
                printOpenSSLError();
                BIO_free(bio);
                return key;
            }
            BIO_free(bio);
            return key;
        }

        EVP_PKEY* RSAPrivateKeyFromPem(const std::string& pemKey) {
            EVP_PKEY* key = nullptr;
            BIO* bio = BIO_new_mem_buf(pemKey.data(), static_cast<int>(pemKey.size()));
            if (!bio) {
                std::cerr << "RSAPrivateKeyFromPem Failed to create memory BIO" << std::endl;
                printOpenSSLError();
                return key;
            }
            if (!PEM_read_bio_PrivateKey(bio, &key, nullptr, nullptr)) {
                std::cerr << "RSAPrivateKeyFromPem Failed to PEM_read_bio_PrivateKey " << std::endl;
                printOpenSSLError();
                BIO_free(bio);
                return key;
            }
            BIO_free(bio);
            return key;
        }

        EVP_PKEY* RSAPrivateKeyFromDer(const std::string& derKey) {
            EVP_PKEY* key = nullptr;
            const unsigned char *in = (const unsigned char *)derKey.data();
            long length = derKey.size();
            if (d2i_PrivateKey(EVP_PKEY_RSA, &key, &in, length) == nullptr) {
                std::cerr << "RSAPublicKeyFromDer Failed to d2i_PrivateKey " << std::endl;
                printOpenSSLError();
                return nullptr;
            }
            return key;
        }

        EVP_PKEY* RSAPrivateKeyFromDerByBio(const std::string& derKey) {
            EVP_PKEY* key = nullptr;
            BIO* bio = BIO_new_mem_buf(derKey.data(), static_cast<int>(derKey.size()));
            if (!bio) {
                std::cerr << "RSAPrivateKeyFromDerByBio Failed to create memory BIO" << std::endl;
                printOpenSSLError();
                return key;
            }
            if (d2i_PrivateKey_bio(bio, &key) == nullptr) {
                std::cerr << "RSAPrivateKeyFromDerByBio Failed to d2i_PrivateKey_bio " << std::endl;
                printOpenSSLError();
                BIO_free(bio);
                return key;
            }
            BIO_free(bio);
            return key;
        }


        EVP_PKEY* RSAPrivateKeyFromBase64(const std::string& base64Key) {
            return RSAPrivateKeyFromDer(base64_decode_url_safe(base64Key));
        }

        EVP_PKEY* RSAPrivateKeyFromHex(const std::string& hexKey) {
            return RSAPrivateKeyFromDer(hex_decode(hexKey));
        }


        int maxRsaEncryptPlainTextSize(EVP_PKEY* pkey, const std::string& paddings) {
            if (paddings == RSA_OAEPPadding) {
                return (EVP_PKEY_bits(pkey) / 8) - 2*20 -2;
            }
            if (paddings == RSA_OAEPwithSHA_256andMGF1Padding) {
                return (EVP_PKEY_bits(pkey) / 8) - 2*32 - 2;
            }

            if (paddings == RSA_OAEPwithSHA_384andMGF1Padding) {
                return (EVP_PKEY_bits(pkey) / 8) - 2*48 - 2;
            }

            if (paddings == RSA_OAEPwithSHA_512andMGF1Padding) {
                return (EVP_PKEY_bits(pkey) / 8) - 2*64 - 2;
            }

            return (EVP_PKEY_bits(pkey) / 8) - 11;//
        }

        int rsaEncryptBlockSize(EVP_PKEY* pkey, const std::string& paddings) {
            return (EVP_PKEY_bits(pkey) / 8);
        }

        int rsaLength(EVP_PKEY* pkey) {
            return (EVP_PKEY_bits(pkey) / 8);
        }


    }
}



namespace camel {
    namespace crypto {

        RSAKeyPairGenerator::RSAKeyPairGenerator(int keyLength) {
            ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
            if (!ctx) {
                std::cerr << "RSAKeyPairGenerator Failed to create EVP_PKEY_CTX" << std::endl;
                printOpenSSLError();
                return;
            }

            if (EVP_PKEY_keygen_init(ctx) <= 0) {
                std::cerr << "Failed to initialize keygen" << std::endl;
                printOpenSSLError();
                clean();
                return;
            }
            int keyBits = 2048;
            if (keyLength == 1024) {
                keyBits = 1024;
            } else if (keyLength == 4096) {
                keyBits = 4096;
            } else if (keyLength == 8192) {
                keyBits = 8192;
            }
            if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, keyBits) <= 0) {
                std::cerr << "Failed to set key length" << std::endl;
                printOpenSSLError();
                clean();
                return;
            }

            if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
                std::cerr << "Failed to generate RSA key pair" << std::endl;
                printOpenSSLError();
                clean();
                return;
            }
        }

        void RSAKeyPairGenerator::clean() {
            if (ctx != nullptr) {
                EVP_PKEY_CTX_free(ctx);
                ctx = nullptr;
            }
            if (pkey != nullptr) {
                EVP_PKEY_free(pkey);
                pkey = nullptr;
            }
        }

        RSAKeyPairGenerator::~RSAKeyPairGenerator() {
            clean();
        }

        std::string RSAKeyPairGenerator::getPublicKey() {
            if (pkey == nullptr) {
                return "";
            }

            BIO* bio = BIO_new(BIO_s_mem());
            if (bio == nullptr) {
                std::cerr << "RSAKeyPairGenerator::getPublicKey() Failed to create memory BIO" << std::endl;
                printOpenSSLError();
                return "";
            }
            if (i2d_PUBKEY_bio(bio, pkey) != 1) {
                std::cerr << "RSAKeyPairGenerator::getPublicKey()Failed to write private key to BIO" << std::endl;
                printOpenSSLError();
                BIO_free(bio);
                return "";
            }
            char* buf;
            long len = BIO_get_mem_data(bio, &buf);
            if (len <= 0) {
                std::cerr << "RSAKeyPairGenerator::getPublicKey() Failed to write private key to BIO" << std::endl;
                printOpenSSLError();
                BIO_free(bio);
                return "";
            }
            std::string der(buf, len);
            BIO_free(bio);
            return der;
        }

        std::string RSAKeyPairGenerator::getPrivateKey() {
            if (pkey == nullptr) {
                return "";
            }
            BIO* bio = BIO_new(BIO_s_mem());
            if (bio == nullptr) {
                std::cerr << "RSAKeyPairGenerator::getPrivateKey() Failed to create memory BIO" << std::endl;
                printOpenSSLError();
                return "";
            }

            if (i2d_PKCS8PrivateKey_bio(bio, pkey, nullptr, nullptr, 0, nullptr, nullptr) != 1) {
                std::cerr << "RSAKeyPairGenerator::getPrivateKey() Failed to write private key to BIO" << std::endl;
                printOpenSSLError();
                BIO_free(bio);
                return "";
            }
            char* buf;
            long len = BIO_get_mem_data(bio, &buf);
            if (len <= 0) {
                std::cerr << "RSAKeyPairGenerator::getPrivateKey() Failed to write private key to BIO" << std::endl;
                printOpenSSLError();
                BIO_free(bio);
                return "";
            }
            std::string der(buf, len);
            BIO_free(bio);
            return der;
        }

        std::string RSAKeyPairGenerator::getHexPublicKey() {
            return hex_encode(getPublicKey());
        }

        std::string RSAKeyPairGenerator::getHexPrivateKey() {
            return hex_encode(getPrivateKey());
        }

        std::string RSAKeyPairGenerator::getBase64NewLinePublicKey() {
            return base64_encode_new_line(getPublicKey());
        }

        std::string RSAKeyPairGenerator::getBase64NewLinePrivateKey() {
            return base64_encode_new_line(getPrivateKey());
        }

        std::string  RSAKeyPairGenerator::getBase64PublicKey() {
            return base64_encode(getPublicKey());
        }
        std::string RSAKeyPairGenerator::getBase64PrivateKey() {
            return base64_encode(getPrivateKey());
        }

        std::string RSAKeyPairGenerator::getPemPrivateKey() {
            if (pkey == nullptr) {
                return "";
            }
            BIO* bio = BIO_new(BIO_s_mem());
            if (bio == nullptr) {
                std::cerr << "RSAKeyPairGenerator::getPemPrivateKey() Failed to create memory BIO" << std::endl;
                printOpenSSLError();
                return "";
            }
            if (PEM_write_bio_PrivateKey(bio, pkey, nullptr, nullptr, 0, nullptr, nullptr) != 1) {
                std::cerr << "RSAKeyPairGenerator::getPemPrivateKey() Failed to write private key to BIO" << std::endl;
                printOpenSSLError();
                BIO_free(bio);
                return "";
            }
            char* bioData = nullptr;
            long bioLen = BIO_get_mem_data(bio, &bioData); // 获取内存地址和长度
            std::string privateKey;
            if (bioLen > 0 && bioData) {
                privateKey.reserve(bioLen);
                privateKey.assign(bioData, bioLen);
            }
            BIO_free(bio);
            return privateKey;
        }

        std::string RSAKeyPairGenerator::getPemPublicKey() {
            if (pkey == nullptr) {
                return "";
            }
            BIO* bio = BIO_new(BIO_s_mem());
            if (bio == nullptr) {
                std::cerr << "RSAKeyPairGenerator::getPemPublicKey() Failed to create memory BIO" << std::endl;
                printOpenSSLError();
                return "";
            }
            if (PEM_write_bio_PUBKEY(bio, pkey) != 1) {
                std::cerr << "RSAKeyPairGenerator::getPemPublicKey() Failed to write private key to BIO" << std::endl;
                printOpenSSLError();
                BIO_free(bio);
                return "";
            }
            char* bioData = nullptr;
            long bioLen = BIO_get_mem_data(bio, &bioData); // 获取内存地址和长度
            std::string publicKey;
            if (bioLen > 0 && bioData) {
                publicKey.reserve(bioLen);
                publicKey.assign(bioData, bioLen);
            }
            BIO_free(bio);
            return publicKey;
        }
    }
}



namespace camel {
    namespace crypto {


        RSAPublicKeyEncryptor::RSAPublicKeyEncryptor(const std::string &publicKey, const std::string &format, const std::string &paddings) {
            this->paddings = paddings;
            this->format = format;
            this->publicKey = publicKey;
            if ("hex" == format) {
                this->pKey = RSAPublicKeyFromHex(publicKey);
            } else if ("base64" == format) {
                this->pKey = RSAPublicKeyFromBase64(publicKey);
            } else if ("der" == format) {
                this->pKey = RSAPublicKeyFromDer(publicKey);
            } else if ("pem" == format) {
                this->pKey = RSAPublicKeyFromPem(publicKey);
            } else {
                this->pKey = RSAPublicKeyFromPem(publicKey);
            }
        }

        std::string RSAPublicKeyEncryptor::encrypt(const std::string_view &plainText) const {
            if (pKey == nullptr || plainText.empty()) {
                return "";
            }
            EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pKey, nullptr);
            if (ctx == nullptr) {
                std::cerr << "RSAPublicKeyEncryptor::encrypt() Failed to create EVP_PKEY_CTX_new " << std::endl;
                printOpenSSLError();
                return "";
            }

            OSSL_PARAM params[5];
            if (paddings == RSA_OAEPPadding) {
                int rsa_pad = RSA_PKCS1_OAEP_PADDING;
                std::string shaName = "SHA-1";
                params[0] = OSSL_PARAM_construct_int("rsa-pad", &rsa_pad);
                params[1] = OSSL_PARAM_construct_utf8_string("rsa-oaep-md", shaName.data(), shaName.size());
                params[2] = OSSL_PARAM_construct_utf8_string("rsa-mgf1-md", shaName.data(), shaName.size());
                params[3] = OSSL_PARAM_END;
            } else if (paddings == RSA_OAEPwithSHA_256andMGF1Padding) {
                int rsa_pad = RSA_PKCS1_OAEP_PADDING;
                std::string shaName = "SHA-256";
                params[0] = OSSL_PARAM_construct_int("rsa-pad", &rsa_pad);
                params[1] = OSSL_PARAM_construct_utf8_string("rsa-oaep-md", shaName.data(), shaName.size());
                params[2] = OSSL_PARAM_construct_utf8_string("rsa-mgf1-md", shaName.data(), shaName.size());
                params[3] = OSSL_PARAM_END;
            } else if (paddings == RSA_OAEPwithSHA_384andMGF1Padding) {
                int rsa_pad = RSA_PKCS1_OAEP_PADDING;
                std::string shaName = "SHA-384";
                params[0] = OSSL_PARAM_construct_int("rsa-pad", &rsa_pad);
                params[1] = OSSL_PARAM_construct_utf8_string("rsa-oaep-md", shaName.data(), shaName.size());
                params[2] = OSSL_PARAM_construct_utf8_string("rsa-mgf1-md", shaName.data(), shaName.size());
                params[3] = OSSL_PARAM_END;
            } else if (paddings == RSA_OAEPwithSHA_512andMGF1Padding) {
                int rsa_pad = RSA_PKCS1_OAEP_PADDING;
                std::string shaName = "SHA-512";
                params[0] = OSSL_PARAM_construct_int("rsa-pad", &rsa_pad);
                params[1] = OSSL_PARAM_construct_utf8_string("rsa-oaep-md", shaName.data(), shaName.size());
                params[2] = OSSL_PARAM_construct_utf8_string("rsa-mgf1-md", shaName.data(), shaName.size());
                params[3] = OSSL_PARAM_END;
            } else {
                int rsa_pad = RSA_PKCS1_PADDING;
                params[0] = OSSL_PARAM_construct_int("rsa-pad", &rsa_pad);
                params[1] = OSSL_PARAM_END;
            }

            if (EVP_PKEY_encrypt_init_ex(ctx, params) <= 0) {
                std::cerr << "RSAPublicKeyEncryptor::encrypt() Failed to EVP_PKEY_encrypt_init_ex " << std::endl;
                printOpenSSLError();
                EVP_PKEY_CTX_free(ctx);
                return "";
            }
            std::string buffer;
            int bigBufferSize = plainText.size()*2;
            buffer.resize(std::max(bigBufferSize, 2048));
            int maxSplitLen = maxRsaEncryptPlainTextSize(pKey, paddings);// max block size
            size_t totalLength = 0;
            unsigned char *in = (unsigned char *)plainText.data();
            unsigned char *out = (unsigned char*) buffer.data();
            for (int remain = plainText.length(); remain > 0; remain -= maxSplitLen) {
                size_t inlen = std::min(remain, maxSplitLen);
                size_t outlen = buffer.size() - totalLength;
                if (EVP_PKEY_encrypt(ctx, out, &outlen, in, inlen) <= 0) {
                    std::cerr << "RSAPublicKeyEncryptor::encrypt() Failed to EVP_PKEY_encrypt " << std::endl;
                    printOpenSSLError();
                    EVP_PKEY_CTX_free(ctx);
                    return "";
                }
                out += outlen;
                in += inlen;
                totalLength += outlen;
            }

            buffer.resize(totalLength);

            EVP_PKEY_CTX_free(ctx);

            return buffer;
        }


        std::string RSAPublicKeyEncryptor::encryptToBase64(const std::string_view &plainText) const {
            return base64_encode(encrypt(plainText));
        }

        std::string RSAPublicKeyEncryptor::encryptToHex(const std::string_view &plainText) const {
            return hex_encode(encrypt(plainText));
        }
    }
}




namespace camel {
    namespace crypto {
        RSAPrivateKeyDecryptor::RSAPrivateKeyDecryptor(const std::string& privateKey,
                  const std::string& format,
                  const std::string& paddings) {
            this->paddings = paddings;
            this->format = format;
            this->privateKey =privateKey;
            if ("hex" == format) {
                this->pKey = RSAPrivateKeyFromHex(privateKey);
            } else if ("base64" == format) {
                this->pKey = RSAPrivateKeyFromBase64(privateKey);
            } else if ("der" == format) {
                this->pKey = RSAPrivateKeyFromDer(privateKey);
            } else if ("pem" == format) {
                this->pKey = RSAPrivateKeyFromPem(privateKey);
            } else {
                this->pKey = RSAPrivateKeyFromPem(privateKey);
            }
        }

        std::string RSAPrivateKeyDecryptor::decrypt(const std::string_view &encryptedData) const {
            if (pKey == nullptr || encryptedData.empty()) {
                return "";
            }
            EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pKey, nullptr);
            if (ctx == nullptr) {
                std::cerr << "RSAPrivateKeyDecryptor::decrypt() Failed to create EVP_PKEY_CTX_new " << std::endl;
                printOpenSSLError();
                return "";
            }

            OSSL_PARAM params[5];
            if (paddings == RSA_OAEPPadding) {
                int rsa_pad = RSA_PKCS1_OAEP_PADDING;
                std::string shaName = "SHA-1";
                params[0] = OSSL_PARAM_construct_int("rsa-pad", &rsa_pad);
                params[1] = OSSL_PARAM_construct_utf8_string("rsa-oaep-md", shaName.data(), shaName.size());
                params[2] = OSSL_PARAM_construct_utf8_string("rsa-mgf1-md", shaName.data(), shaName.size());
                params[3] = OSSL_PARAM_END;
            } else if (paddings == RSA_OAEPwithSHA_256andMGF1Padding) {
                int rsa_pad = RSA_PKCS1_OAEP_PADDING;
                std::string shaName = "SHA-256";
                params[0] = OSSL_PARAM_construct_int("rsa-pad", &rsa_pad);
                params[1] = OSSL_PARAM_construct_utf8_string("rsa-oaep-md", shaName.data(), shaName.size());
                params[2] = OSSL_PARAM_construct_utf8_string("rsa-mgf1-md", shaName.data(), shaName.size());
                params[3] = OSSL_PARAM_END;
            }else if (paddings == RSA_OAEPwithSHA_384andMGF1Padding) {
                int rsa_pad = RSA_PKCS1_OAEP_PADDING;
                std::string shaName = "SHA-384";
                params[0] = OSSL_PARAM_construct_int("rsa-pad", &rsa_pad);
                params[1] = OSSL_PARAM_construct_utf8_string("rsa-oaep-md", shaName.data(), shaName.size());
                params[2] = OSSL_PARAM_construct_utf8_string("rsa-mgf1-md", shaName.data(), shaName.size());
                params[3] = OSSL_PARAM_END;
            }else if (paddings == RSA_OAEPwithSHA_512andMGF1Padding) {
                int rsa_pad = RSA_PKCS1_OAEP_PADDING;
                std::string shaName = "SHA-512";
                params[0] = OSSL_PARAM_construct_int("rsa-pad", &rsa_pad);
                params[1] = OSSL_PARAM_construct_utf8_string("rsa-oaep-md", shaName.data(), shaName.size());
                params[2] = OSSL_PARAM_construct_utf8_string("rsa-mgf1-md", shaName.data(), shaName.size());
                params[3] = OSSL_PARAM_END;
            }else {
                int rsa_pad = RSA_PKCS1_PADDING;
                params[0] = OSSL_PARAM_construct_int("rsa-pad", &rsa_pad);
                params[1] = OSSL_PARAM_END;
            }

            if (EVP_PKEY_decrypt_init_ex(ctx, params) <= 0) {
                std::cerr << "RSAPrivateKeyDecryptor::decrypt() Failed to EVP_PKEY_encrypt_init_ex " << std::endl;
                printOpenSSLError();
                EVP_PKEY_CTX_free(ctx);
                return "";
            }
            std::string buffer;
            int bigBufferSize = encryptedData.size();
            buffer.resize(std::max(bigBufferSize, 1024));
            int rsaBlockSize = rsaEncryptBlockSize(pKey, paddings);// max block size
            if (encryptedData.length() % rsaBlockSize != 0) {
                std::cerr << "RSAPrivateKeyDecryptor::decrypt() invalid rsa encrypt data " << std::endl;
                return "";
            }
            size_t totalLength = 0;
            unsigned char *in = (unsigned char *)encryptedData.data();
            unsigned char *out = (unsigned char*) buffer.data();
            for (int remain = encryptedData.length(); remain > 0; remain -= rsaBlockSize) {
                size_t outlen =  buffer.size() - totalLength;
                size_t inlen = std::min(remain, rsaBlockSize);
                if (EVP_PKEY_decrypt(ctx, out, &outlen, in, inlen) <= 0) {
                    std::cerr << "RSAPrivateKeyDecryptor::decrypt() Failed to EVP_PKEY_decrypt " << std::endl;
                    printOpenSSLError();
                    EVP_PKEY_CTX_free(ctx);
                    return "";
                }
                out += outlen;
                in += inlen;
                totalLength += outlen;
            }

            buffer.resize(totalLength);

            EVP_PKEY_CTX_free(ctx);

            return buffer;
        }

        std::string RSAPrivateKeyDecryptor::decryptFromHex(const std::string_view &encryptedText) const {
            return decrypt(hex_decode(encryptedText));
        }

        std::string RSAPrivateKeyDecryptor::decryptFromBase64(const std::string_view &encryptedText) const {
            return decrypt(base64_decode_url_safe(encryptedText));
        }

    }
}