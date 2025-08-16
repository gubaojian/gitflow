//
// Created by efurture on 25-8-16.
//

#include "test_digest.h"

#include <iostream>
#include <string>
#include <__ostream/basic_ostream.h>

#include "../common/digest.h"


namespace camel {
    namespace crypto {
        void testDigest() {
            std::string plainData = "hello world rsa";
            bool passed = true;
            {
                MessageDigest digest("MD5");
                std::cout << digest.digestToHex(plainData) << std::endl;
                passed = passed && digest.digestToHex(plainData) == "8499052ebf277794da966f9bfec2793a";
            }
            {
                MessageDigest digest("SHA1");
                std::cout << digest.digestToHex(plainData) << std::endl;
                passed = passed && digest.digestToHex(plainData) == "8d6921f621721dbb5976ef7710337c027941d60d";
            }
            {
                MessageDigest digest("SHA2-256");
                std::cout << digest.digestToHex(plainData) << std::endl;
                passed = passed && digest.digestToHex(plainData) == "5ca2bc5c4b3bd91cf7a0f425aebeb49a615a70c0b97f5229ea5b12119591dc7b";
            }

            {
                MessageDigest digest("SHA2-384");
                std::cout << digest.digestToHex(plainData) << std::endl;
                passed = passed && digest.digestToHex(plainData) == "6fe2d9da745dcb8ef1cba6bbf4c1bbeac7a521a8cb51a590ad2efa27ee88917dd51e040c5980586dba40372289dcbc05";
            }

            {
                MessageDigest digest("SHA2-512");
                std::string hash = "62cf1b6d9aea41752e05b1a25a3d976dc8ef606dc96bbb692bf7ad91a84054721f015b9533f948872993320c6d1c108ae7a9968b725ee926454bcf272308840e";
                std::cout << digest.digestToHex(plainData) << std::endl;
                passed = passed && digest.digestToHex(plainData) == hash;
            }

            {
                MessageDigest digest("SHA3-256");
                std::string hash = "00f154eb6c3845467b7bf705f73bfa3821b8c6ebc90af2472ff906bf60368a67";
                std::cout << digest.digestToHex(plainData) << std::endl;
                passed = passed && digest.digestToHex(plainData) == hash;
            }

            {
                MessageDigest digest("SHA3-384");
                std::string hash = "665a30c7dc8bd194e60836b5e178156b7c5ebcd18f627f6945f74449e98e46293b0d501e3b89c0f737da0de9f9a821d5";
                std::cout << digest.digestToHex(plainData) << std::endl;
                passed = passed && digest.digestToHex(plainData) == hash;
            }

            {
                MessageDigest digest("SHA3-512");
                std::string hash = "94a6ac505dc94019b4f88bc32355bd8e5f2bcf61f8c11a19b61694434af68aa6f6cd6df5145a34bcbdd3d0b4b16b16dab7afa4d2093b2f0f9b621665bb42acca";
                std::cout << digest.digestToHex(plainData) << std::endl;
                passed = passed && digest.digestToHex(plainData) == hash;
            }

            {
                MessageDigest digest("SHA2-512/224");
                std::string hash = "cb71dc9044cd9dece103ab281ba56352d5c189e1b81d515571970aa2";
                std::cout << digest.digestToHex(plainData) << std::endl;
                passed = passed && digest.digestToHex(plainData) == hash;
            }

            {
                MessageDigest digest("SHA2-512/256");
                std::string hash = "ffbc2b5bd86ecafc96bfbf392b5618e0e18990f6e7fb08aeef7633c844c40044";
                std::cout << digest.digestToHex(plainData) << std::endl;
                passed = passed && digest.digestToHex(plainData) == hash;
            }

            {
                MessageDigest digest("SM3");
                std::string hash = "62858be86c822b17763b34de6b85671c8ec7c133a106a42e9b4503ac33bfba47";
                std::cout << digest.digestToHex(plainData) << std::endl;
                passed = passed && digest.digestToHex(plainData) == hash;
            }

            {
                MessageDigest digest("RIPEMD160");
                std::string hash = "a2653d0c7031e4cc274cdae944bb67d4af84f445";
                std::cout << digest.digestToHex(plainData) << std::endl;
                passed = passed && digest.digestToHex(plainData) == hash;
            }


            {
                MessageDigest digest("KECCAK-KMAC-128");
                std::string hash = "9e5b80c888e9f30a1fd2f0b9c8e9b2014b018752dfffaccb0e2389ff59eac0c0";
                std::cout << digest.digestToHex(plainData) << std::endl;
                passed = passed && digest.digestToHex(plainData) == hash;
            }

            {
                MessageDigest digest("KECCAK-KMAC-256");
                std::string hash = "2051a359fdd7f8a4a35c094affe3d5338ace909f06b4472f9a43d1f67fa2997cc65ed613783e0fa3a60c5178877b662efa35b6e71bb9e5d18b3a45048e58b7c3";
                std::cout << digest.digestToHex(plainData) << std::endl;
                passed = passed && digest.digestToHex(plainData) == hash;
            }

            {
                MessageDigest digest("MD5-SHA1");
                std::string hash = "8499052ebf277794da966f9bfec2793a8d6921f621721dbb5976ef7710337c027941d60d";
                std::cout << digest.digestToHex(plainData) << std::endl;
                passed = passed && digest.digestToHex(plainData) == hash;
            }

            {
                MessageDigest digest("BLAKE2b512");
                std::string hash = "70ef25e53601512140ff61ac3d4e33e55abbb0855054101e151184bd70c08c72f30676fbed592ce7cbf7dd88883eb56a1c693b673ab5befbeb3e0d257a6eba84";
                std::cout << digest.digestToHex(plainData) << std::endl;
                passed = passed && digest.digestToHex(plainData) == hash;
            }

            {
                MessageDigest digest("BLAKE2s256");
                std::string hash = "2268b1ec879567f51e8eb600e085a3e9445cdd2d187119bdb1c4b3bf8f526a0b";
                std::cout << digest.digestToHex(plainData) << std::endl;
                passed = passed && digest.digestToHex(plainData) == hash;
            }


            {
                XOFMessageDigest digest("SHAKE256", 64);
                std::string hash = "ee59e56778271ce61de46e2226ecacce10a98a983bfa5f00947a408b821c00592d338c6aefb87628846b94214f1637afad22fede8253ccaf5e187aab594b120e";
                std::cout << digest.digestToHex(plainData) << std::endl;
                passed = passed && digest.digestToHex(plainData) == hash;
            }

            {
                XOFMessageDigest digest("SHAKE128", 32);
                std::string hash = "e37b1c32b38bc323dcae868530088753a1f1a3f54273b15f3ed627bd141e8809";
                std::cout << digest.digestToHex(plainData) << std::endl;
                passed = passed && digest.digestToHex(plainData) == hash;
            }

            {
                XOFMessageDigest digest("SHAKE128", 256);
                std::string hash = "e37b1c32b38bc323dcae868530088753a1f1a3f54273b15f3ed627bd141e880924da328dcba5c5e1a88a48b97e92a9bcfe57a78b1232974b36ac8d83448efd0a459e3d05a768bfeb8f52fbf5f5b5b2debdea96793d17d0c33d06ff7867d753eb63ece30fb2c01702180f5f934b0cee9ab132dd1243c88e4d65c210830c58702f4e2f76e7b663188790e9942fc1036158240d349b74cd15e345daa7277570d8118f40b3ed5a342af596edc2c0bb001658712ace213b375eb79e3fcaf0262faa3249940970e5ed1fbee3144280e0a1df4ff7d5fde67d8ffd1a0e88b4b35a20233267aae9a5cc6cc1626bdfbcf6df223555c249ecd5b3156a0c0527ab9cb7dbf064";
                std::cout << digest.digestToHex(plainData) << std::endl;
                passed = passed && digest.digestToHex(plainData) == hash;
            }















            if (passed) {
                std::cout << "testDigest() passed " << std::endl;
            } else {
                std::cout << "testDigest() failed " << std::endl;
            }
        }
    }
}
