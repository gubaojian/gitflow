//
// Created by baojian on 25-8-5.
//

#include "rsa.h"
#include <iostream>
#include <openssl/rsa.h>

#include "base64.h"
#include "common.h"
#include "hex.h"
#include "openssl/core_names.h"



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


        EVP_PKEY* RSAPublicKeyFrom(const std::string& publicKey, const std::string& format) {
            if ("hex" == format) {
                return RSAPublicKeyFromHex(publicKey);
            } else if ("base64" == format) {
                return RSAPublicKeyFromBase64(publicKey);
            } else if ("der" == format) {
                return RSAPublicKeyFromDer(publicKey);
            } else if ("pem" == format) {
                return RSAPublicKeyFromPem(publicKey);
            } else {
                return RSAPublicKeyFromPem(publicKey);
            }
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

        EVP_PKEY* RSAPrivateKeyFrom(const std::string& privateKey, const std::string& format) {
            if ("hex" == format) {
                return RSAPrivateKeyFromHex(privateKey);
            } else if ("base64" == format) {
                return RSAPrivateKeyFromBase64(privateKey);
            } else if ("der" == format) {
               return RSAPrivateKeyFromDer(privateKey);
            } else if ("pem" == format) {
               return RSAPrivateKeyFromPem(privateKey);
            } else {
                return RSAPrivateKeyFromPem(privateKey);
            }
        }


        inline int maxRsaEncryptPlainTextSize(EVP_PKEY* pkey, const std::string& paddings) {
            if (paddings == RSA_PKCS1Padding) { //RSA_PKCS1Padding
                return (EVP_PKEY_bits(pkey) / 8) - 11;
            }
            if (paddings == RSA_OAEPPadding
                || paddings == RSA_OAEPWithSHA_1AndMGF1Padding) {
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

            if (paddings == RSA_OAEP_SHA3_256_MGF1_SHA3_256) {
                return (EVP_PKEY_bits(pkey) / 8) - 2*32 - 2;
            }

            if (paddings == RSA_OAEP_SHA3_512_MGF1_SHA3_512) {
                return (EVP_PKEY_bits(pkey) / 8) - 2*64 - 2;
            }

            int minSize = (EVP_PKEY_bits(pkey) / 8) - 2*64 - 2;
            if (minSize <= 0) {
                minSize = (EVP_PKEY_bits(pkey) / 8) - 2*32 - 2;
            }
            return minSize;
        }

        int rsaEncryptBlockSize(EVP_PKEY* pkey, const std::string& paddings) {
            return (EVP_PKEY_bits(pkey) / 8);
        }
        int rsaMaxSignSize(EVP_PKEY* pkey) {
            int size = (EVP_PKEY_bits(pkey) / 8);
            if (size <= 1024) {
                size = 1024;
            }
            return size;
        }

        int rsaLength(EVP_PKEY* pkey) {
            return (EVP_PKEY_bits(pkey) / 8);
        }

        bool configEncryptParams(EVP_PKEY_CTX *ctx, const std::string& paddings) {
          if (paddings == RSA_OAEPPadding) {
                std::string paddingMode = OSSL_PKEY_RSA_PAD_MODE_OAEP;
                std::string mainHash = OSSL_DIGEST_NAME_SHA1;
                std::string mgf1Hash = OSSL_DIGEST_NAME_SHA1;
                OSSL_PARAM params[] = {
                  OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_PAD_MODE,
                                               paddingMode.data(), paddingMode.size()),
                  OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST, mainHash.data(), mainHash.size()),
                  OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST, mgf1Hash.data(), mgf1Hash.size()),
                  OSSL_PARAM_END
                 };
                if (EVP_PKEY_encrypt_init_ex(ctx, params) <= 0) {
                    std::cerr << "configEncryptParams Failed to EVP_PKEY_encrypt_init_ex " << paddings << std::endl;
                    printOpenSSLError();
                    return false;
                }
                return true;
            } else if (paddings == RSA_OAEPWithSHA_1AndMGF1Padding) {
                std::string paddingMode = OSSL_PKEY_RSA_PAD_MODE_OAEP;
                std::string mainHash = OSSL_DIGEST_NAME_SHA1;
                std::string mgf1Hash = OSSL_DIGEST_NAME_SHA1;
                OSSL_PARAM params[] = {
                    OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_PAD_MODE,
                                                 paddingMode.data(), paddingMode.size()),
                    OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST, mainHash.data(), mainHash.size()),
                    OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST, mgf1Hash.data(), mgf1Hash.size()),
                    OSSL_PARAM_END
                };
                if (EVP_PKEY_encrypt_init_ex(ctx, params) <= 0) {
                    std::cerr << "configEncryptParams Failed to EVP_PKEY_encrypt_init_ex " << paddings << std::endl;
                    printOpenSSLError();
                    return false;
                }
                return true;
            } else if (paddings == RSA_OAEPwithSHA_256andMGF1Padding) {
                std::string paddingMode = OSSL_PKEY_RSA_PAD_MODE_OAEP;
                std::string mainHash = OSSL_DIGEST_NAME_SHA2_256;
                std::string mgf1Hash = OSSL_DIGEST_NAME_SHA1;
                OSSL_PARAM params[] = {
                    OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_PAD_MODE,
                                                 paddingMode.data(), paddingMode.size()),
                    OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST, mainHash.data(), mainHash.size()),
                    OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST, mgf1Hash.data(), mgf1Hash.size()),
                    OSSL_PARAM_END
                };
                if (EVP_PKEY_encrypt_init_ex(ctx, params) <= 0) {
                    std::cerr << "configEncryptParams Failed to EVP_PKEY_encrypt_init_ex " << paddings << std::endl;
                    printOpenSSLError();
                    return false;
                }
                return true;
            } else if (paddings == RSA_OAEPwithSHA_384andMGF1Padding) {
                std::string paddingMode = OSSL_PKEY_RSA_PAD_MODE_OAEP;
                std::string mainHash = OSSL_DIGEST_NAME_SHA2_384;
                std::string mgf1Hash = OSSL_DIGEST_NAME_SHA1;
                OSSL_PARAM params[] = {
                    OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_PAD_MODE,
                                                 paddingMode.data(), paddingMode.size()),
                    OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST, mainHash.data(), mainHash.size()),
                    OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST, mgf1Hash.data(), mgf1Hash.size()),
                    OSSL_PARAM_END
                };
                if (EVP_PKEY_encrypt_init_ex(ctx, params) <= 0) {
                    std::cerr << "configEncryptParams Failed to EVP_PKEY_encrypt_init_ex " << paddings << std::endl;
                    printOpenSSLError();
                    return false;
                }
                return true;
            } else if (paddings == RSA_OAEPwithSHA_512andMGF1Padding) {
                std::string paddingMode = OSSL_PKEY_RSA_PAD_MODE_OAEP;
                std::string mainHash = OSSL_DIGEST_NAME_SHA2_512;
                std::string mgf1Hash = OSSL_DIGEST_NAME_SHA1;
                OSSL_PARAM params[] = {
                    OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_PAD_MODE,
                                                 paddingMode.data(), paddingMode.size()),
                    OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST, mainHash.data(), mainHash.size()),
                    OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST, mgf1Hash.data(), mgf1Hash.size()),
                    OSSL_PARAM_END
                };
                if (EVP_PKEY_encrypt_init_ex(ctx, params) <= 0) {
                    std::cerr << "configEncryptParams Failed to EVP_PKEY_encrypt_init_ex " << paddings << std::endl;
                    printOpenSSLError();
                    return false;
                }
                return true;
            } else if (paddings == RSA_PKCS1Padding) {
                // RSA_PKCS1_PADDING
                std::string paddingMode = OSSL_PKEY_RSA_PAD_MODE_PKCSV15;
                OSSL_PARAM params[] = {
                    OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_PAD_MODE,
                                                 paddingMode.data(), paddingMode.size()),
                     OSSL_PARAM_END
                };
                if (EVP_PKEY_encrypt_init_ex(ctx, params) <= 0) {
                    std::cerr << "configEncryptParams Failed to EVP_PKEY_encrypt_init_ex " << paddings << std::endl;
                    printOpenSSLError();
                    return false;
                }
                return true;
            }else if (paddings ==  RSA_OAEP_SHA256_MGF1_SHA256) {
                std::string paddingMode = OSSL_PKEY_RSA_PAD_MODE_OAEP;
                std::string mainHash = OSSL_DIGEST_NAME_SHA2_256;
                std::string mgf1Hash = OSSL_DIGEST_NAME_SHA2_256;
                OSSL_PARAM params[] = {
                    OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_PAD_MODE,
                                                 paddingMode.data(), paddingMode.size()),
                    OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST, mainHash.data(), mainHash.size()),
                    OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST, mgf1Hash.data(), mgf1Hash.size()),
                    OSSL_PARAM_END
                };
                if (EVP_PKEY_encrypt_init_ex(ctx, params) <= 0) {
                    std::cerr << "configEncryptParams Failed to EVP_PKEY_encrypt_init_ex " << paddings << std::endl;
                    printOpenSSLError();
                    return false;
                }
                return true;
            }else if (paddings ==  RSA_OAEP_SHA512_MGF1_SHA512) {
                std::string paddingMode = OSSL_PKEY_RSA_PAD_MODE_OAEP;
                std::string mainHash = OSSL_DIGEST_NAME_SHA2_512;
                std::string mgf1Hash = OSSL_DIGEST_NAME_SHA2_512;
                OSSL_PARAM params[] = {
                    OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_PAD_MODE,
                                                 paddingMode.data(), paddingMode.size()),
                    OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST, mainHash.data(), mainHash.size()),
                    OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST, mgf1Hash.data(), mgf1Hash.size()),
                    OSSL_PARAM_END
                };
                if (EVP_PKEY_encrypt_init_ex(ctx, params) <= 0) {
                    std::cerr << "configEncryptParams Failed to EVP_PKEY_encrypt_init_ex " << paddings << std::endl;
                    printOpenSSLError();
                    return false;
                }
                return true;
            }else if (paddings ==  RSA_OAEP_SHA3_256_MGF1_SHA3_256) {
                std::string paddingMode = OSSL_PKEY_RSA_PAD_MODE_OAEP;
                std::string mainHash = OSSL_DIGEST_NAME_SHA3_256;
                std::string mgf1Hash = OSSL_DIGEST_NAME_SHA3_256;
                OSSL_PARAM params[] = {
                    OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_PAD_MODE,
                                                 paddingMode.data(), paddingMode.size()),
                    OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST, mainHash.data(), mainHash.size()),
                    OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST, mgf1Hash.data(), mgf1Hash.size()),
                    OSSL_PARAM_END
                };
                if (EVP_PKEY_encrypt_init_ex(ctx, params) <= 0) {
                    std::cerr << "configEncryptParams Failed to EVP_PKEY_encrypt_init_ex " << paddings << std::endl;
                    printOpenSSLError();
                    return false;
                }
                return true;
            }else if (paddings ==  RSA_OAEP_SHA3_512_MGF1_SHA3_512) {
                std::string paddingMode = OSSL_PKEY_RSA_PAD_MODE_OAEP;
                std::string mainHash = OSSL_DIGEST_NAME_SHA3_512;
                std::string mgf1Hash = OSSL_DIGEST_NAME_SHA3_512;
                OSSL_PARAM params[] = {
                    OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_PAD_MODE,
                                                 paddingMode.data(), paddingMode.size()),
                    OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST, mainHash.data(), mainHash.size()),
                    OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST, mgf1Hash.data(), mgf1Hash.size()),
                    OSSL_PARAM_END
                };
                if (EVP_PKEY_encrypt_init_ex(ctx, params) <= 0) {
                    std::cerr << "configEncryptParams Failed to EVP_PKEY_encrypt_init_ex " << paddings << std::endl;
                    printOpenSSLError();
                    return false;
                }
                return true;
            }
            std::cerr << "configEncryptParams unsupported mode " << paddings << std::endl;
            return false;
        }

        bool configDecryptParams(EVP_PKEY_CTX *ctx, const std::string& paddings) {
            if (paddings == RSA_OAEPPadding) {
                std::string paddingMode = OSSL_PKEY_RSA_PAD_MODE_OAEP;
                std::string mainHash = OSSL_DIGEST_NAME_SHA1;
                std::string mgf1Hash = OSSL_DIGEST_NAME_SHA1;
                OSSL_PARAM params[] = {
                    OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_PAD_MODE,
                                                 paddingMode.data(), paddingMode.size()),
                    OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST, mainHash.data(), mainHash.size()),
                    OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST, mgf1Hash.data(), mgf1Hash.size()),
                    OSSL_PARAM_END
                };
                if (EVP_PKEY_decrypt_init_ex(ctx, params) <= 0) {
                    std::cerr << "configDecryptParams Failed to EVP_PKEY_decrypt_init_ex " << paddings << std::endl;
                    printOpenSSLError();
                    return false;
                }
                return true;
            } else if (paddings == RSA_OAEPWithSHA_1AndMGF1Padding) {
                std::string paddingMode = OSSL_PKEY_RSA_PAD_MODE_OAEP;
                std::string mainHash = OSSL_DIGEST_NAME_SHA1;
                std::string mgf1Hash = OSSL_DIGEST_NAME_SHA1;
                OSSL_PARAM params[] = {
                    OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_PAD_MODE,
                                                 paddingMode.data(), paddingMode.size()),
                    OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST, mainHash.data(), mainHash.size()),
                    OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST, mgf1Hash.data(), mgf1Hash.size()),
                    OSSL_PARAM_END
                };
                if (EVP_PKEY_decrypt_init_ex(ctx, params) <= 0) {
                    std::cerr << "configDecryptParams Failed to EVP_PKEY_decrypt_init_ex " << paddings << std::endl;
                    printOpenSSLError();
                    return false;
                }
                return true;
            } else if (paddings == RSA_OAEPwithSHA_256andMGF1Padding) {
                std::string paddingMode = OSSL_PKEY_RSA_PAD_MODE_OAEP;
                std::string mainHash = OSSL_DIGEST_NAME_SHA2_256;
                std::string mgf1Hash = OSSL_DIGEST_NAME_SHA1;
                OSSL_PARAM params[] = {
                    OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_PAD_MODE,
                                                 paddingMode.data(), paddingMode.size()),
                    OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST, mainHash.data(), mainHash.size()),
                    OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST, mgf1Hash.data(), mgf1Hash.size()),
                    OSSL_PARAM_END
                };
                if (EVP_PKEY_decrypt_init_ex(ctx, params) <= 0) {
                    std::cerr << "configDecryptParams Failed to EVP_PKEY_decrypt_init_ex " << paddings << std::endl;
                    printOpenSSLError();
                    return false;
                }
                return true;
            } else if (paddings == RSA_OAEPwithSHA_384andMGF1Padding) {
                std::string paddingMode = OSSL_PKEY_RSA_PAD_MODE_OAEP;
                std::string mainHash = OSSL_DIGEST_NAME_SHA2_384;
                std::string mgf1Hash = OSSL_DIGEST_NAME_SHA1;
                OSSL_PARAM params[] = {
                    OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_PAD_MODE,
                                                 paddingMode.data(), paddingMode.size()),
                    OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST, mainHash.data(), mainHash.size()),
                    OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST, mgf1Hash.data(), mgf1Hash.size()),
                    OSSL_PARAM_END
                };
                if (EVP_PKEY_decrypt_init_ex(ctx, params) <= 0) {
                    std::cerr << "configDecryptParams Failed to EVP_PKEY_decrypt_init_ex " << paddings << std::endl;
                    printOpenSSLError();
                    return false;
                }
                return true;
            } else if (paddings == RSA_OAEPwithSHA_512andMGF1Padding) {
                std::string paddingMode = OSSL_PKEY_RSA_PAD_MODE_OAEP;
                std::string mainHash = OSSL_DIGEST_NAME_SHA2_512;
                std::string mgf1Hash = OSSL_DIGEST_NAME_SHA1;
                OSSL_PARAM params[] = {
                    OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_PAD_MODE,
                                                 paddingMode.data(), paddingMode.size()),
                    OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST, mainHash.data(), mainHash.size()),
                    OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST, mgf1Hash.data(), mgf1Hash.size()),
                    OSSL_PARAM_END
                };
                if (EVP_PKEY_decrypt_init_ex(ctx, params) <= 0) {
                    std::cerr << "configDecryptParams Failed to EVP_PKEY_decrypt_init_ex " << paddings << std::endl;
                    printOpenSSLError();
                    return false;
                }
                return true;
            } else if (paddings == RSA_PKCS1Padding) {
                // RSA_PKCS1_PADDING
                std::string paddingMode = OSSL_PKEY_RSA_PAD_MODE_PKCSV15;
                OSSL_PARAM params[] = {
                    OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_PAD_MODE,
                                                 paddingMode.data(), paddingMode.size()),
                     OSSL_PARAM_END
                };
                if (EVP_PKEY_decrypt_init_ex(ctx, params) <= 0) {
                    std::cerr << "configDecryptParams Failed to EVP_PKEY_decrypt_init_ex " << paddings << std::endl;
                    printOpenSSLError();
                    return false;
                }
                return true;
            }else if (paddings ==  RSA_OAEP_SHA256_MGF1_SHA256) {
                std::string paddingMode = OSSL_PKEY_RSA_PAD_MODE_OAEP;
                std::string mainHash = OSSL_DIGEST_NAME_SHA2_256;
                std::string mgf1Hash = OSSL_DIGEST_NAME_SHA2_256;
                OSSL_PARAM params[] = {
                    OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_PAD_MODE,
                                                 paddingMode.data(), paddingMode.size()),
                    OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST, mainHash.data(), mainHash.size()),
                    OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST, mgf1Hash.data(), mgf1Hash.size()),
                    OSSL_PARAM_END
                };
                if (EVP_PKEY_decrypt_init_ex(ctx, params) <= 0) {
                    std::cerr << "configDecryptParams Failed to EVP_PKEY_decrypt_init_ex " << paddings << std::endl;
                    printOpenSSLError();
                    return false;
                }
                return true;
            }else if (paddings ==  RSA_OAEP_SHA512_MGF1_SHA512) {
                std::string paddingMode = OSSL_PKEY_RSA_PAD_MODE_OAEP;
                std::string mainHash = OSSL_DIGEST_NAME_SHA2_512;
                std::string mgf1Hash = OSSL_DIGEST_NAME_SHA2_512;
                OSSL_PARAM params[] = {
                    OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_PAD_MODE,
                                                 paddingMode.data(), paddingMode.size()),
                    OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST, mainHash.data(), mainHash.size()),
                    OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST, mgf1Hash.data(), mgf1Hash.size()),
                    OSSL_PARAM_END
                };
                if (EVP_PKEY_decrypt_init_ex(ctx, params) <= 0) {
                    std::cerr << "configDecryptParams Failed to EVP_PKEY_decrypt_init_ex " << paddings << std::endl;
                    printOpenSSLError();
                    return false;
                }
                return true;
            }else if (paddings ==  RSA_OAEP_SHA3_256_MGF1_SHA3_256) {
                std::string paddingMode = OSSL_PKEY_RSA_PAD_MODE_OAEP;
                std::string mainHash = OSSL_DIGEST_NAME_SHA3_256;
                std::string mgf1Hash = OSSL_DIGEST_NAME_SHA3_256;
                OSSL_PARAM params[] = {
                    OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_PAD_MODE,
                                                 paddingMode.data(), paddingMode.size()),
                    OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST, mainHash.data(), mainHash.size()),
                    OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST, mgf1Hash.data(), mgf1Hash.size()),
                    OSSL_PARAM_END
                };
                if (EVP_PKEY_decrypt_init_ex(ctx, params) <= 0) {
                    std::cerr << "configDecryptParams Failed to EVP_PKEY_decrypt_init_ex " << paddings << std::endl;
                    printOpenSSLError();
                    return false;
                }
                return true;
            }else if (paddings ==  RSA_OAEP_SHA3_512_MGF1_SHA3_512) {
                std::string paddingMode = OSSL_PKEY_RSA_PAD_MODE_OAEP;
                std::string mainHash = OSSL_DIGEST_NAME_SHA3_512;
                std::string mgf1Hash = OSSL_DIGEST_NAME_SHA3_512;
                OSSL_PARAM params[] = {
                    OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_PAD_MODE,
                                                 paddingMode.data(), paddingMode.size()),
                    OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST, mainHash.data(), mainHash.size()),
                    OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST, mgf1Hash.data(), mgf1Hash.size()),
                    OSSL_PARAM_END
                };
                if (EVP_PKEY_decrypt_init_ex(ctx, params) <= 0) {
                    std::cerr << "configDecryptParams Failed to EVP_PKEY_decrypt_init_ex " << paddings << std::endl;
                    printOpenSSLError();
                    return false;
                }
                return true;
            }
            std::cerr << "configDecryptParams unsupported mode " << paddings << std::endl;
            return false;
        }

        inline bool algorithmHas(const std::string& algorithm, std::string_view target) {
            return algorithm.find(target) != std::string::npos;
        }

        bool configSignParams(EVP_MD_CTX* ctx,  EVP_PKEY* key, const std::string& algorithm) {
            std::string paddingMode = OSSL_PKEY_RSA_PAD_MODE_PKCS1;
            std::string signHash = OSSL_DIGEST_NAME_SHA2_256;

            if (algorithmHas(algorithm,"PSS")) {
                paddingMode = OSSL_PKEY_RSA_PAD_MODE_PSS;
            }
            if (algorithmHas(algorithm,"MD5withRSA")) {
                signHash = OSSL_DIGEST_NAME_MD5;
            } else if (algorithmHas(algorithm,"SHA1withRSA")) {
                signHash = OSSL_DIGEST_NAME_SHA1;
            } else if (algorithmHas(algorithm,"SHA256withRSA")) {
                signHash = OSSL_DIGEST_NAME_SHA2_256;
            } else if (algorithmHas(algorithm,"SHA384withRSA")) {
                signHash = OSSL_DIGEST_NAME_SHA2_384;
            } else if (algorithmHas(algorithm,"SHA512withRSA")) {
                signHash = OSSL_DIGEST_NAME_SHA2_256;
            } else if (algorithmHas(algorithm,"SHA512/224withRSA")) {
                signHash = OSSL_DIGEST_NAME_SHA2_512_224;
            } else if (algorithmHas(algorithm,"SHA512/256withRSA")) {
                signHash = OSSL_DIGEST_NAME_SHA2_512_256;
            } else if (algorithmHas(algorithm,"SHA3_256withRSA")) {
                signHash = OSSL_DIGEST_NAME_SHA3_256;
            } else if (algorithmHas(algorithm,"SHA3_384withRSA")) {
                signHash = OSSL_DIGEST_NAME_SHA3_384;
            } else if (algorithmHas(algorithm,"SHA3_512withRSA")) {
                signHash = OSSL_DIGEST_NAME_SHA3_512;
            }
            OSSL_PARAM params[] = {
                OSSL_PARAM_construct_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE,
                                             paddingMode.data(), paddingMode.size()),
                OSSL_PARAM_END
            };
            if (EVP_DigestSignInit_ex(ctx, NULL, signHash.data(), nullptr, nullptr,
                            key, params) == 0) {
                printOpenSSLError();
                return false;
            }
            return true;
        }

         bool configVerifyParams(EVP_MD_CTX* ctx,  EVP_PKEY* key, const std::string& algorithm) {
            std::string paddingMode = OSSL_PKEY_RSA_PAD_MODE_PKCS1;
            std::string signHash = OSSL_DIGEST_NAME_SHA2_256;

            if (algorithmHas(algorithm,"PSS")) {
                paddingMode = OSSL_PKEY_RSA_PAD_MODE_PSS;
            }
            if (algorithmHas(algorithm,"MD5withRSA")) {
                signHash = OSSL_DIGEST_NAME_MD5;
            } else if (algorithmHas(algorithm,"SHA1withRSA")) {
                signHash = OSSL_DIGEST_NAME_SHA1;
            } else if (algorithmHas(algorithm,"SHA256withRSA")) {
                signHash = OSSL_DIGEST_NAME_SHA2_256;
            } else if (algorithmHas(algorithm,"SHA384withRSA")) {
                signHash = OSSL_DIGEST_NAME_SHA2_384;
            } else if (algorithmHas(algorithm,"SHA512withRSA")) {
                signHash = OSSL_DIGEST_NAME_SHA2_256;
            } else if (algorithmHas(algorithm,"SHA512/224withRSA")) {
                signHash = OSSL_DIGEST_NAME_SHA2_512_224;
            } else if (algorithmHas(algorithm,"SHA512/256withRSA")) {
                signHash = OSSL_DIGEST_NAME_SHA2_512_256;
            } else if (algorithmHas(algorithm,"SHA3_256withRSA")) {
                signHash = OSSL_DIGEST_NAME_SHA3_256;
            } else if (algorithmHas(algorithm,"SHA3_384withRSA")) {
                signHash = OSSL_DIGEST_NAME_SHA3_384;
            } else if (algorithmHas(algorithm,"SHA3_512withRSA")) {
                signHash = OSSL_DIGEST_NAME_SHA3_512;
            }
            OSSL_PARAM params[] = {
                OSSL_PARAM_construct_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE,
                                             paddingMode.data(), paddingMode.size()),
                OSSL_PARAM_END
            };
            if (EVP_DigestVerifyInit_ex(ctx, NULL, signHash.data(), nullptr, nullptr,
                            key, params) == 0) {
                printOpenSSLError();
                return false;
            }
            return true;
        }


        class EvpKeyGuard {
        public:
            explicit EvpKeyGuard(EVP_PKEY* evpKey, bool needFree) {
                this->evpKey = evpKey;
                this->needFree = needFree;
            }
            ~EvpKeyGuard() {
                if (needFree) {
                    if (evpKey != nullptr) {
                        EVP_PKEY_free(evpKey);
                        evpKey = nullptr;
                    }
                }
            }
        public:
            EvpKeyGuard(EvpKeyGuard const&)            = delete;
            EvpKeyGuard& operator=(EvpKeyGuard const&) = delete;
        private:
            EVP_PKEY* evpKey;
            bool  needFree;
        };

        class EvpKeyCtxGuard {
        public:
            explicit EvpKeyCtxGuard(EVP_PKEY_CTX* ctx) {
                this->ctx = ctx;
            }
            ~EvpKeyCtxGuard() {
                if (ctx != nullptr) {
                    EVP_PKEY_CTX_free(ctx);
                    ctx = nullptr;
                }
            }
        public:
            EvpKeyCtxGuard(EvpKeyCtxGuard const&)            = delete;
            EvpKeyCtxGuard& operator=(EvpKeyCtxGuard const&) = delete;
        private:
            EVP_PKEY_CTX* ctx;
        };



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


        RSAPublicKeyEncryptor::RSAPublicKeyEncryptor(const std::string_view &publicKey, const std::string_view &format, const std::string_view &paddings) {
            this->paddings = paddings;
            this->format = format;
            this->publicKey = publicKey;
            this->externalEvpKey = nullptr;
        }

        std::string RSAPublicKeyEncryptor::encrypt(const std::string_view &plainText) const {
            if (plainText.empty()) {
                return "";
            }
            EVP_PKEY* evpKey = externalEvpKey;
            if (evpKey == nullptr) {
                evpKey = RSAPublicKeyFrom(publicKey, format);
            }
            if (evpKey == nullptr) {
                return "";
            }
            EvpKeyGuard evpKeyGuard(evpKey, externalEvpKey == nullptr);
            EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(evpKey, nullptr);
            if (ctx == nullptr) {
                std::cerr << "RSAPublicKeyEncryptor::encrypt() Failed to create EVP_PKEY_CTX_new " << std::endl;
                printOpenSSLError();
                return "";
            }

            if (!configEncryptParams(ctx, paddings)) {
                EVP_PKEY_CTX_free(ctx);
                return "";
            }

            std::string buffer;
            int bigBufferSize = plainText.size()*2;
            buffer.resize(std::max(bigBufferSize, 2048));
            int maxSplitLen = maxRsaEncryptPlainTextSize(evpKey, paddings);// max block size
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
        RSAPrivateKeyDecryptor::RSAPrivateKeyDecryptor(const std::string_view& privateKey,
                  const std::string_view& format,
                  const std::string_view& paddings) {
            this->paddings = paddings;
            this->format = format;
            this->privateKey = privateKey;
            this->externalEvpKey = nullptr;
        }

        std::string RSAPrivateKeyDecryptor::decrypt(const std::string_view &encryptedData) {
            if (encryptedData.empty()) {
                return "";
            }

            EVP_PKEY* evpKey = externalEvpKey;
            if (evpKey == nullptr) {
                evpKey = RSAPrivateKeyFrom(privateKey, format);
            }
            if (evpKey == nullptr) {
                return "";
            }
            EvpKeyGuard evpKeyGuard(evpKey, externalEvpKey == nullptr);

            EVP_PKEY_CTX * ctx = EVP_PKEY_CTX_new(evpKey, nullptr);

            if (ctx == nullptr) {
                std::cerr << "RSAPrivateKeyDecryptor::decrypt() Failed to create EVP_PKEY_CTX_new " << std::endl;
                printOpenSSLError();
                return "";
            }

            if (!configDecryptParams(ctx, paddings)) {
                EVP_PKEY_CTX_free(ctx);
                return "";
            }

            std::string buffer;
            int bigBufferSize = encryptedData.size();
            buffer.resize(std::max(bigBufferSize, 1024));
            int rsaBlockSize = rsaEncryptBlockSize(evpKey, paddings);// max block size
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

        std::string RSAPrivateKeyDecryptor::decryptFromHex(const std::string_view &encryptedText){
            std::string data = hex_decode(encryptedText);
            return decrypt(data);
        }

        std::string RSAPrivateKeyDecryptor::decryptFromBase64(const std::string_view &encryptedText) {
            std::string data = base64_decode_url_safe(encryptedText);
            return decrypt(data);
        }

    }
}



namespace camel {
    namespace crypto {
        RSAPrivateKeySigner::RSAPrivateKeySigner(const std::string_view& privateKey,
                  const std::string_view& format,
                  const std::string_view& algorithm) {
            this->algorithm = algorithm;
            this->format = format;
            this->privateKey = privateKey;
            this->externalEvpKey = nullptr;
        }


        std::string RSAPrivateKeySigner::sign(const std::string_view &plainText) const {
            if (plainText.empty()) {
                return "";
            }

            EVP_PKEY* evpKey = externalEvpKey;
            if (evpKey == nullptr) {
                evpKey = RSAPrivateKeyFrom(privateKey, format);
            }
            if (evpKey == nullptr) {
                return "";
            }
            EvpKeyGuard evpKeyGuard(evpKey, externalEvpKey == nullptr);

            EVP_MD_CTX* ctx = EVP_MD_CTX_new();
            if (ctx == nullptr) {
                std::cerr << "RSAPrivateKeySigner::sign() Failed to create EVP_MD_CTX_new() " << std::endl;
                printOpenSSLError();
                return "";
            }
            if (!configSignParams(ctx, evpKey, algorithm)) {
                EVP_MD_CTX_free(ctx);
                return "";
            }
            if (EVP_DigestSignUpdate(ctx, plainText.data(), plainText.size()) == 0) {
                std::cerr << "RSAPrivateKeySigner::sign() Failed to EVP_DigestSignUpdate " << std::endl;
                printOpenSSLError();
                EVP_MD_CTX_free(ctx);
                return "";
            }

            std::string buffer;
            buffer.resize(rsaMaxSignSize(evpKey));
            unsigned char *out = (unsigned char*) buffer.data();
            size_t outlen =  buffer.size();
            if (EVP_DigestSignFinal(ctx, out, &outlen) == 0) {
                std::cerr << "RSAPrivateKeySigner::sign() Failed to EVP_DigestSignFinal " << std::endl;
                printOpenSSLError();
                EVP_MD_CTX_free(ctx);
                return "";
            }
            EVP_MD_CTX_free(ctx);
            buffer.resize(outlen);

            return buffer;
        }

        std::string RSAPrivateKeySigner::signToHex(const std::string_view &plainText) const {
            return hex_encode(sign(plainText));
        }

        std::string RSAPrivateKeySigner::signToBase64(const std::string_view &plainText) const {
            return base64_encode(sign(plainText));
        }

    }
}


namespace camel {
    namespace crypto {
        RSAPublicKeyVerifier::RSAPublicKeyVerifier(const std::string_view& publicKey,
                  const std::string_view& format,
                  const std::string_view& algorithm) {
            this->algorithm = algorithm;
            this->format = format;
            this->publicKey = publicKey;
        }


        bool RSAPublicKeyVerifier::verifySign(const std::string_view &sign, const std::string_view &data) const {
            if (sign.empty()
                || data.empty()) {
                return false;
            }

            EVP_PKEY* evpKey = externalEvpKey;
            if (evpKey == nullptr) {
                evpKey = RSAPublicKeyFrom(publicKey, format);
            }
            if (evpKey == nullptr) {
                std::cerr << "RSAPrivateKeyVerifier::verifySign() Failed to create EVP_PKEY " << std::endl;
                printOpenSSLError();
                return false;
            }
            EvpKeyGuard evpKeyGuard(evpKey, externalEvpKey == nullptr);

            EVP_MD_CTX* ctx = EVP_MD_CTX_new();
            if (ctx == nullptr) {
                std::cerr << "RSAPrivateKeyVerifier::verifySign() Failed to create EVP_MD_CTX_new() " << std::endl;
                printOpenSSLError();
                return false;
            }
            if (!configVerifyParams(ctx, evpKey, algorithm)) {
                EVP_MD_CTX_free(ctx);
                return false;
            }
            if (EVP_DigestVerifyUpdate(ctx, data.data(), data.size()) == 0) {
                std::cerr << "RSAPrivateKeyVerifier::verifySign() Failed to EVP_DigestVerifyUpdate " << std::endl;
                printOpenSSLError();
                EVP_MD_CTX_free(ctx);
                return false;
            }

            unsigned char *signData = (unsigned char*) sign.data();
            if (EVP_DigestVerifyFinal(ctx, signData, sign.size()) == 0) {
                std::cerr << "RSAPrivateKeyVerifier::verifySign() Failed to EVP_DigestVerifyFinal " << std::endl;
                printOpenSSLError();
                EVP_MD_CTX_free(ctx);
                return false;
            }
            EVP_MD_CTX_free(ctx);
            return true;
        }

        bool RSAPublicKeyVerifier::verifyHexSign(const std::string_view &hexSign, const std::string_view &data) const {
            std::string sign = hex_decode(hexSign);
            return verifySign(sign, data);
        }


        bool RSAPublicKeyVerifier::verifyBase64Sign(const std::string_view &base64Sign, const std::string_view &data) const {
            std::string sign = base64_decode_url_safe(base64Sign);
            return verifySign(sign, data);
        }

    }
}

namespace camel {
    namespace crypto {

        inline std::string rsaPublicEncrypt(const std::string_view& paddings,
            const std::string_view& publicKey,
            const std::string_view& format,
            const std::string_view& data,
            EVP_PKEY* externalPublicKey) {
            RSAPublicKeyEncryptor encryptor(publicKey, format, paddings);
            if (externalPublicKey != nullptr) {
                encryptor.setExternalEvpKey(externalPublicKey);
            }
            return encryptor.encrypt(data);
        }

        inline std::string rsaPublicEncryptToHex(const std::string_view& paddings,
            const std::string_view& publicKey,
            const std::string_view& format,
            const std::string_view& data,
            EVP_PKEY* externalPublicKey) {
            RSAPublicKeyEncryptor encryptor(publicKey, format, paddings);
            if (externalPublicKey != nullptr) {
                encryptor.setExternalEvpKey(externalPublicKey);
            }
            return encryptor.encryptToHex(data);
        }

        inline std::string rsaPublicEncryptToBase64(const std::string_view& paddings,
            const std::string_view& publicKey,
            const std::string_view& format,
            const std::string_view& data,
            EVP_PKEY* externalPublicKey) {
            RSAPublicKeyEncryptor encryptor(publicKey, format, paddings);
            if (externalPublicKey != nullptr) {
                encryptor.setExternalEvpKey(externalPublicKey);
            }
            return encryptor.encryptToBase64(data);
        }

        inline std::string rsaPrivateDecrypt(const std::string_view& paddings,
            const std::string_view& privateKey,
            const std::string_view& format,
            const std::string_view& data,
            EVP_PKEY* externalPrivateKey) {
            RSAPrivateKeyDecryptor decryptor(privateKey, format, paddings);
            if ( externalPrivateKey != nullptr) {
                decryptor.setExternalEvpKey( externalPrivateKey);
            }
            return decryptor.decrypt(data);
        }

        inline std::string rsaPrivateDecryptFromHex(const std::string_view& paddings,
            const std::string_view& privateKey,
            const std::string_view& format,
            const std::string_view& data,
            EVP_PKEY* externalPrivateKey) {
            RSAPrivateKeyDecryptor decryptor(privateKey, format, paddings);
            if ( externalPrivateKey != nullptr) {
                decryptor.setExternalEvpKey( externalPrivateKey);
            }
            return decryptor.decryptFromHex(data);
        }

        inline std::string rsaPrivateDecryptFromBase64(const std::string_view& paddings,
            const std::string_view& privateKey,
            const std::string_view& format,
            const std::string_view& data,
            EVP_PKEY* externalPrivateKey) {
            RSAPrivateKeyDecryptor decryptor(privateKey, format, paddings);
            if ( externalPrivateKey != nullptr) {
                decryptor.setExternalEvpKey( externalPrivateKey);
            }
            return decryptor.decryptFromBase64(data);
        }

        namespace RSAPKCS1Utils {

            std::string encrypt(const std::string_view& publicKey,  const std::string_view& format, const std::string_view& data) {
                return rsaPublicEncrypt("PKCS1Padding", publicKey, format, data, nullptr);
            }

            std::string encryptToHex(const std::string_view& publicKey,  const std::string_view& format, const std::string_view& data) {
                return rsaPublicEncryptToHex("PKCS1Padding", publicKey, format, data, nullptr);
            }
            std::string encryptToBase64(const std::string_view& publicKey,  const std::string_view& format, const std::string_view& data) {
                return rsaPublicEncryptToBase64("PKCS1Padding", publicKey, format, data, nullptr);
            }

            std::string decrypt(const std::string_view& privateKey,const std::string_view& format,  const std::string_view& data) {
                return rsaPrivateDecrypt("PKCS1Padding", privateKey, format, data, nullptr);
            }
            std::string decryptFromHex(const std::string_view& privateKey,const std::string_view& format,  const std::string_view& data) {
                return rsaPrivateDecryptFromHex("PKCS1Padding", privateKey, format, data, nullptr);
            }
            std::string decryptFromBase64(const std::string_view& privateKey,const std::string_view& format,  const std::string_view& data) {
                return rsaPrivateDecryptFromBase64("PKCS1Padding", privateKey, format, data, nullptr);
            }

            // 复用EVP_PKEY，减少key解析创建开销, 复用key，速度快一些
            std::string encryptByEVPKey(EVP_PKEY* publicKey, const std::string_view& data) {
                return rsaPublicEncrypt("PKCS1Padding", "", "", data, publicKey);
            }
            std::string encryptByEVPKeyToHex(EVP_PKEY* publicKey, const std::string_view& data) {
                return rsaPublicEncryptToHex("PKCS1Padding", "", "", data, publicKey);
            }
            std::string encryptByEVPKeyToBase64(EVP_PKEY* publicKey, const std::string_view& data) {
                return rsaPublicEncryptToBase64("PKCS1Padding", "", "", data, publicKey);
            }

            std::string decryptByEvpKey(EVP_PKEY* privateKey,  const std::string_view& data) {
                return rsaPrivateDecrypt("PKCS1Padding", "", "", data, privateKey);
            }
            std::string decryptByEvpKeyFromHex(EVP_PKEY* privateKey,  const std::string_view& data) {
                return rsaPrivateDecryptFromHex("PKCS1Padding", "", "", data, privateKey);
            }
            std::string decryptByEvpKeyFromBase64(EVP_PKEY* privateKey,  const std::string_view& data) {
                return rsaPrivateDecryptFromBase64("PKCS1Padding", "", "", data, privateKey);
            }
        }

        namespace RSAOAEPSha256AndMGF1PaddingUtils {
            std::string encrypt(const std::string_view& publicKey,  const std::string_view& format, const std::string_view& data) {
                return rsaPublicEncrypt("RSA_OAEPwithSHA_256andMGF1Padding", publicKey, format, data, nullptr);
            }
            std::string encryptToHex(const std::string_view& publicKey,  const std::string_view& format, const std::string_view& data) {
                return rsaPublicEncryptToHex("RSA_OAEPwithSHA_256andMGF1Padding", publicKey, format, data, nullptr);
            }
            std::string encryptToBase64(const std::string_view& publicKey,  const std::string_view& format, const std::string_view& data) {
                return rsaPublicEncryptToBase64("RSA_OAEPwithSHA_256andMGF1Padding", publicKey, format, data, nullptr);
            }

            std::string decrypt(const std::string_view& privateKey,const std::string_view& format,  const std::string_view& data) {
                return rsaPrivateDecrypt("RSA_OAEPwithSHA_256andMGF1Padding", privateKey, format, data, nullptr);
            }
            std::string decryptFromHex(const std::string_view& privateKey,const std::string_view& format,  const std::string_view& data) {
                return rsaPrivateDecryptFromHex("RSA_OAEPwithSHA_256andMGF1Padding", privateKey, format, data, nullptr);
            }
            std::string decryptFromBase64(const std::string_view& privateKey,const std::string_view& format,  const std::string_view& data) {
                return rsaPrivateDecryptFromBase64("RSA_OAEPwithSHA_256andMGF1Padding", privateKey, format, data, nullptr);
            }

            // 复用EVP_PKEY，减少key解析创建开销, 复用key，速度快一些
            std::string encryptByEVPKey(EVP_PKEY* publicKey, const std::string_view& data) {
                return rsaPublicEncrypt("RSA_OAEPwithSHA_256andMGF1Padding", "", "", data, publicKey);
            }
            std::string encryptByEVPKeyToHex(EVP_PKEY* publicKey, const std::string_view& data) {
                return rsaPublicEncryptToHex("RSA_OAEPwithSHA_256andMGF1Padding", "", "", data, publicKey);
            }
            std::string encryptByEVPKeyToBase64(EVP_PKEY* publicKey, const std::string_view& data) {
                return rsaPublicEncryptToBase64("RSA_OAEPwithSHA_256andMGF1Padding", "", "", data, publicKey);
            }

            std::string decryptByEvpKey(EVP_PKEY* privateKey,  const std::string_view& data) {
                return rsaPrivateDecrypt("RSA_OAEPwithSHA_256andMGF1Padding", "", "", data, privateKey);
            }
            std::string decryptByEvpKeyFromHex(EVP_PKEY* privateKey,  const std::string_view& data) {
                return rsaPrivateDecryptFromHex("RSA_OAEPwithSHA_256andMGF1Padding", "", "", data, privateKey);
            }
            std::string decryptByEvpKeyFromBase64(EVP_PKEY* privateKey,  const std::string_view& data) {
                return rsaPrivateDecryptFromBase64("RSA_OAEPwithSHA_256andMGF1Padding", "", "", data, privateKey);
            }
        }

    }
}


namespace camel {
    namespace crypto {
        inline bool rsaPublicVerify(const std::string_view& algorithm,
            const std::string_view& publicKey,
            const std::string_view& format,
            const std::string_view& data,
            const std::string_view& sign,
            EVP_PKEY* externalPublicKey) {
            RSAPublicKeyVerifier verifier(publicKey, format, algorithm);
            if (externalPublicKey != nullptr) {
                verifier.setExternalEvpKey(externalPublicKey);
            }
            return verifier.verifySign(sign, data);
        }

        inline bool rsaPublicVerifyHexSign(const std::string_view& algorithm,
            const std::string_view& publicKey,
            const std::string_view& format,
            const std::string_view& data,
            const std::string_view& sign,
            EVP_PKEY* externalPublicKey) {
            RSAPublicKeyVerifier verifier(publicKey, format, algorithm);
            if (externalPublicKey != nullptr) {
                verifier.setExternalEvpKey(externalPublicKey);
            }
            return verifier.verifyHexSign(sign, data);
        }

        inline bool rsaPublicVerifyBase64Sign(const std::string_view& algorithm,
            const std::string_view& publicKey,
            const std::string_view& format,
            const std::string_view& data,
            const std::string_view& sign,
            EVP_PKEY* externalPublicKey) {
            RSAPublicKeyVerifier verifier(publicKey, format, algorithm);
            if (externalPublicKey != nullptr) {
                verifier.setExternalEvpKey(externalPublicKey);
            }
            return verifier.verifyBase64Sign(sign, data);
        }

        inline std::string rsaPrivateSign(const std::string_view&  algorithm,
            const std::string_view& privateKey,
            const std::string_view& format,
            const std::string_view& data,
            EVP_PKEY* externalPrivateKey) {
            RSAPrivateKeySigner signer(privateKey, format, algorithm);
            if ( externalPrivateKey != nullptr) {
                signer.setExternalEvpKey( externalPrivateKey);
            }
            return signer.sign(data);
        }

        inline std::string rsaPrivateSignToHex(const std::string_view&  algorithm,
            const std::string_view& privateKey,
            const std::string_view& format,
            const std::string_view& data,
            EVP_PKEY* externalPrivateKey) {
            RSAPrivateKeySigner signer(privateKey, format, algorithm);
            if ( externalPrivateKey != nullptr) {
                signer.setExternalEvpKey( externalPrivateKey);
            }
            return signer.signToHex(data);
        }

        inline std::string rsaPrivateSignToBase64(const std::string_view&  algorithm,
            const std::string_view& privateKey,
            const std::string_view& format,
            const std::string_view& data,
            EVP_PKEY* externalPrivateKey) {
            RSAPrivateKeySigner signer(privateKey, format, algorithm);
            if ( externalPrivateKey != nullptr) {
                signer.setExternalEvpKey( externalPrivateKey);
            }
            return signer.signToBase64(data);
        }


        /**
         * 默认 PKCS1 填充， Java默认签名填充方式
         */
        namespace RSAPKCS1Sha256SignUtils {

            std::string sign(const std::string_view& privateKey,const std::string_view& format,  const std::string_view& data) {
                return rsaPrivateSign("SHA256withRSA", privateKey, format, data, nullptr);
            }

            std::string signToHex(const std::string_view& privateKey,const std::string_view& format,  const std::string_view& data) {
                return rsaPrivateSignToHex("SHA256withRSA", privateKey, format, data, nullptr);
            }
            std::string signToBase64(const std::string_view& privateKey,const std::string_view& format,  const std::string_view& data) {
                return rsaPrivateSignToBase64("SHA256withRSA", privateKey, format, data, nullptr);
            }

            bool verify(const std::string_view& publicKey,  const std::string_view& format, const std::string_view& data, const std::string_view& sign) {
                return rsaPublicVerify("SHA256withRSA", publicKey, format, data, sign, nullptr);
            }
            bool verifyHexSign(const std::string_view& publicKey,  const std::string_view& format, const std::string_view& data, const std::string_view& sign) {
                return rsaPublicVerifyHexSign("SHA256withRSA", publicKey, format, data, sign, nullptr);
            }
            bool verifyBase64Sign(const std::string_view& publicKey,  const std::string_view& format, const std::string_view& data, const std::string_view& sign) {
                return rsaPublicVerifyBase64Sign("SHA256withRSA", publicKey, format, data, sign, nullptr);
            }

            // 复用EVP_PKEY，减少key解析创建开销, 复用key，速度快一些
            std::string signByEVPKey(EVP_PKEY* privateKey, const std::string_view& data) {
                return rsaPrivateSign("SHA256withRSA", "", "", data, privateKey);
            }
            std::string signByEVPKeyToHex(EVP_PKEY* privateKey, const std::string_view& data) {
                return rsaPrivateSignToHex("SHA256withRSA", "", "", data, privateKey);
            }
            std::string signByEVPKeyToBase64(EVP_PKEY* privateKey, const std::string_view& data) {
                return rsaPrivateSignToBase64("SHA256withRSA", "", "", data, privateKey);
            }

            bool verifyByEVPKey(EVP_PKEY* publicKey,  const std::string_view& data, const std::string_view& sign) {
                return rsaPublicVerify("SHA256withRSA", "", "", data, sign, publicKey);
            }
            bool verifyHexSignByEVPKey(EVP_PKEY* publicKey,  const std::string_view& data, const std::string_view& sign) {
                return rsaPublicVerifyHexSign("SHA256withRSA", "", "", data, sign, publicKey);
            }
            bool verifyBase64SignByEVPKey(EVP_PKEY* publicKey,  const std::string_view& data, const std::string_view& sign) {
                return rsaPublicVerifyBase64Sign("SHA256withRSA", "", "", data, sign, publicKey);
            }
        }

        /**
         * 默认 PSS 填充
         */
         namespace RSAPSSSha256SignUtils {

            std::string sign(const std::string_view& privateKey,const std::string_view& format,  const std::string_view& data) {
                return rsaPrivateSign("SHA256withRSA/PSS", privateKey, format, data, nullptr);
            }

            std::string signToHex(const std::string_view& privateKey,const std::string_view& format,  const std::string_view& data) {
                return rsaPrivateSignToHex("SHA256withRSA/PSS", privateKey, format, data, nullptr);
            }
            std::string signToBase64(const std::string_view& privateKey,const std::string_view& format,  const std::string_view& data) {
                return rsaPrivateSignToBase64("SHA256withRSA/PSS", privateKey, format, data, nullptr);
            }

            bool verify(const std::string_view& publicKey,  const std::string_view& format, const std::string_view& data, const std::string_view& sign) {
                return rsaPublicVerify("SHA256withRSA/PSS", publicKey, format, data, sign, nullptr);
            }
            bool verifyHexSign(const std::string_view& publicKey,  const std::string_view& format, const std::string_view& data, const std::string_view& sign) {
                return rsaPublicVerifyHexSign("SHA256withRSA/PSS", publicKey, format, data, sign, nullptr);
            }
            bool verifyBase64Sign(const std::string_view& publicKey,  const std::string_view& format, const std::string_view& data, const std::string_view& sign) {
                return rsaPublicVerifyBase64Sign("SHA256withRSA/PSS", publicKey, format, data, sign, nullptr);
            }

            // 复用EVP_PKEY，减少key解析创建开销, 复用key，速度快一些
            std::string signByEVPKey(EVP_PKEY* privateKey, const std::string_view& data) {
                return rsaPrivateSign("SHA256withRSA/PSS", "", "", data, privateKey);
            }
            std::string signByEVPKeyToHex(EVP_PKEY* privateKey, const std::string_view& data) {
                return rsaPrivateSignToHex("SHA256withRSA/PSS", "", "", data, privateKey);
            }
            std::string signByEVPKeyToBase64(EVP_PKEY* privateKey, const std::string_view& data) {
                return rsaPrivateSignToBase64("SHA256withRSA/PSS", "", "", data, privateKey);
            }

            bool verifyByEVPKey(EVP_PKEY* publicKey,  const std::string_view& data, const std::string_view& sign) {
                return rsaPublicVerify("SHA256withRSA/PSS", "", "", data, sign, publicKey);
            }
            bool verifyHexSignByEVPKey(EVP_PKEY* publicKey,  const std::string_view& data, const std::string_view& sign) {
                return rsaPublicVerifyHexSign("SHA256withRSA/PSS", "", "", data, sign, publicKey);
            }
            bool verifyBase64SignByEVPKey(EVP_PKEY* publicKey,  const std::string_view& data, const std::string_view& sign) {
                return rsaPublicVerifyBase64Sign("SHA256withRSA/PSS", "", "", data, sign, publicKey);
            }
        }




    }
}