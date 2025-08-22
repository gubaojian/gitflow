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
#include "test/test_chacha20.h"
#include "test/test_digest.h"
#include "test/test_ec.h"
#include "test/test_hmac.h"
#include "test/test_rsa.h"
#include "test/test_sm2.h"


using namespace camel::crypto;

void runAllTests() {
    testHex();
    testBase64();
    testRsaGenerateKey();
    testRsaWithJava();
    testRsaSign();
    testHmac();
    testDigest();
    testSM2KeyGen();
    testSM2KeyEncrypt();
    testSM2KeySigner();

    testChaCha20KeyGen();
    testChaCha20KeyEncrypt();
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

   // testEcKeyGen();
   // testEcKeyEncrypt();
    testEcKeyGen();
    testEcDHKeyGen();


}



int main() {
    camel::crypto::initLibCrypto();

    runAllTests();
    runAllDemos();



    camel::crypto::cleanupLibCrypto();

    return 0;
}
