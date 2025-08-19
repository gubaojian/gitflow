#include "common/config.h"
#include "common/rsa.h"
#include "common/hex.h"
#include "common/base64.h"
#include "test/test_rsa.h"
#include "common/file_utils.h"
#include "test/test_base64.h"
#include "test/test_hex.h"
#include "demo/demo_rsa.h"
#include "demo/demo_aes.h"
#include <iostream>
#include <cstdio>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <string>
#include <fstream>
#include <stdexcept>
#include "demo/demo_hmac.h"
#include "test/test_digest.h"
#include "test/test_ec.h"
#include "test/test_hmac.h"
#include "test/test_rsa.h"


using namespace camel::crypto;

void runAllTests() {
    testRsaGenerateKey();
    testRsaWithJava();
    testRsaSign();
    testHex();
    testBase64();
    testHmac();
    testDigest();
    testEcKeyGen();
}

void runAllDemos() {
   demoRsaGenerateKey();
   demoRsaEncrypt();
   demoRsaSign();
   demoAesGenerateKey();
   demoAesEncrypt();
    //demoWithJava();
   //demoRsaCryptPerf();
   //demoRsaDecryptPerf();
   //demoHmac();
   //demoHmacPerf();

    testEcKeyGen();
    testEcKeyEncrypt();

}


// 打印对称加密算法（如AES、DES等）
void print_symmetric_ciphers() {
    std::cout << "\n=== 支持的对称加密算法 ===" << std::endl;
    std::cout << std::left << std::setw(30) << "算法名称"
              << std::setw(10) << "块大小"
              << std::setw(10) << "密钥长度" << std::endl;
    std::cout << std::string(50, '-') << std::endl;

    // 遍历所有对称加密算法
    EVP_CIPHER_do_all([](const EVP_CIPHER *ciph,
                                   const char *from, const char *to, void *x) {
        std::cout << from << std::endl;
    }, nullptr);
}



// 打印KEM密钥封装算法（如ECIES、Kyber等）
void print_kem_algorithms() {
    std::cout << "\n=== 支持的KEM密钥封装算法 ===" << std::endl;

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    // 遍历所有KEM算法（OpenSSL 3.0+支持）
    EVP_KEM_do_all_provided(nullptr, [](EVP_KEM* kem, void* arg) {
        const char* name = EVP_KEM_get0_name(kem);
        const char* desc = EVP_KEM_get0_description(kem);
        std::cout << "- " << name;
        if (desc && *desc != '\0') {
            std::cout << " (" << desc << ")";
        }
        std::cout << std::endl;
    }, nullptr);
#else
    std::cout << "注意：OpenSSL 3.0+ 才支持KEM算法枚举" << std::endl;
#endif
}

int main() {
    camel::crypto::initLibCrypto();

    runAllTests();
    runAllDemos();


    // 打印各类加密算法
    print_symmetric_ciphers();    // 对称加密（AES、DES等）
    print_kem_algorithms();       // KEM密钥封装算法

    camel::crypto::cleanupLibCrypto();

    return 0;
}
