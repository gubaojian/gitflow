#include "common/config.h"
#include "common/rsa.h"
#include "common/hex.h"
#include "common/base64.h"
#include "test/test_rsa.h"
#include "common/file_utils.h"
#include "test/test_base64.h"
#include "test/test_hex.h"
#include "demo/demo_rsa.h"
#include <iostream>
#include <cstdio>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <string>
#include <fstream>
#include <stdexcept>
#include "demo/demo_hmac.h"
#include "test/test_hmac.h"
#include "test/test_rsa.h"


using namespace camel::crypto;

void runAllTests() {
    testRsaGenerateKey();
    testRsaWithJava();
    testHex();
    testBase64();
    testHmac();
}

void runAllDemos() {
   demoRsaGenerateKey();
   demoRsaEncrypt();
    demoWithJava();
   //demoRsaCryptPerf();
   //demoRsaDecryptPerf();
   //demoHmac();
   //demoHmacPerf();
}

int main() {
    camel::crypto::initLibCrypto();

    runAllTests();
    runAllDemos();



    camel::crypto::cleanupLibCrypto();

    return 0;
}
