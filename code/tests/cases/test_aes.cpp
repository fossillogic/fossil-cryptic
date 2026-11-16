/**
 * -----------------------------------------------------------------------------
 * Project: Fossil Logic
 *
 * This file is part of the Fossil Logic project, which aims to develop
 * high-performance, cross-platform applications and libraries. The code
 * contained herein is licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License. You may obtain
 * a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 *
 * Author: Michael Gene Brockus (Dreamer)
 * Date: 04/05/2013
 *
 * Copyright (C) 2013-Current Fossil Logic. All rights reserved.
 * -----------------------------------------------------------------------------
 */
#include <fossil/maip/framework.h>
#include "fossil/cryptic/framework.h"


// * * * * * * * * * * * * * * * * * * * * * * * *
// * Fossil Logic Test Utilities
// * * * * * * * * * * * * * * * * * * * * * * * *
// Setup steps for things like test fixtures and
// mock objects are set here.
// * * * * * * * * * * * * * * * * * * * * * * * *

FOSSIL_SUITE(cpp_aes_fixture);

FOSSIL_SETUP(cpp_aes_fixture) {
    // Setup the test fixture
}

FOSSIL_TEARDOWN(cpp_aes_fixture) {
    // Teardown the test fixture
}

// * * * * * * * * * * * * * * * * * * * * * * * *
// * Fossil Logic Test Cases
// * * * * * * * * * * * * * * * * * * * * * * * *
// The test cases below are provided as samples, inspired
// by the Meson build system's approach of using test cases
// as samples for library usage.
// * * * * * * * * * * * * * * * * * * * * * * * *

FOSSIL_TEST(cpp_test_aes_gcm_encrypt_decrypt_roundtrip) {
    const uint8_t key[32] = {0};
    const uint8_t nonce[12] = {0};
    const uint8_t ad[] = {0x01, 0x02, 0x03};
    const uint8_t plaintext[] = {0x10, 0x20, 0x30, 0x40, 0x50};
    uint8_t ciphertext[sizeof(plaintext) + 16];
    uint8_t decrypted[sizeof(plaintext)];

    ASSUME_ITS_EQUAL_I32(fossil::cryptic::Aes::encrypt(
        ciphertext, key, nonce, ad, sizeof(ad), plaintext, sizeof(plaintext)), 0);
    ASSUME_ITS_EQUAL_I32(fossil::cryptic::Aes::decrypt(
        decrypted, key, nonce, ad, sizeof(ad), ciphertext, sizeof(plaintext)), 0);
    ASSUME_ITS_TRUE(memcmp(decrypted, plaintext, sizeof(plaintext)) == 0);
}

FOSSIL_TEST(cpp_test_aes_gcm_nist_vector) {
    const uint8_t key[32] = {0};
    const uint8_t nonce[12] = {0};
    const uint8_t plaintext[16] = {0};
    const uint8_t expected[32] = {
        0xce, 0xa7, 0x40, 0x3d, 0x4d, 0x60, 0x66, 0xb6,
        0xe0, 0x74, 0xec, 0x5d, 0x3b, 0xaf, 0x39, 0xd1,
        0x8d, 0xd0, 0xd1, 0xc8, 0xa7, 0x99, 0x96, 0xbf,
        0x02, 0x65, 0xb9, 0x8b, 0x5d, 0x48, 0xab, 0x91
    };
    uint8_t ciphertext[sizeof(expected)];

    ASSUME_ITS_EQUAL_I32(fossil::cryptic::Aes::encrypt(
        ciphertext, key, nonce, nullptr, 0, plaintext, sizeof(plaintext)), 0);
    ASSUME_ITS_TRUE(memcmp(ciphertext, expected, sizeof(expected)) == 0);
}

FOSSIL_TEST(cpp_test_aes_gcm_encrypt_null_params) {
    const uint8_t key[32] = {0};
    const uint8_t nonce[12] = {0};
    const uint8_t ad[] = {0x01};
    const uint8_t plaintext[] = {0x02};
    uint8_t ciphertext[sizeof(plaintext) + 16];

    ASSUME_ITS_EQUAL_I32(fossil::cryptic::Aes::encrypt(
        nullptr, key, nonce, ad, sizeof(ad), plaintext, sizeof(plaintext)), -1);
    ASSUME_ITS_EQUAL_I32(fossil::cryptic::Aes::encrypt(
        ciphertext, nullptr, nonce, ad, sizeof(ad), plaintext, sizeof(plaintext)), -1);
    ASSUME_ITS_EQUAL_I32(fossil::cryptic::Aes::encrypt(
        ciphertext, key, nullptr, ad, sizeof(ad), plaintext, sizeof(plaintext)), -1);
    ASSUME_ITS_EQUAL_I32(fossil::cryptic::Aes::encrypt(
        ciphertext, key, nonce, nullptr, sizeof(ad), plaintext, sizeof(plaintext)), -1);
    ASSUME_ITS_EQUAL_I32(fossil::cryptic::Aes::encrypt(
        ciphertext, key, nonce, ad, sizeof(ad), nullptr, sizeof(plaintext)), -1);
}

FOSSIL_TEST(cpp_test_aes_gcm_decrypt_null_params) {
    const uint8_t key[32] = {0};
    const uint8_t nonce[12] = {0};
    const uint8_t ad[] = {0x01};
    const uint8_t ciphertext[17] = {0};
    uint8_t plaintext[1];

    ASSUME_ITS_EQUAL_I32(fossil::cryptic::Aes::decrypt(
        nullptr, key, nonce, ad, sizeof(ad), ciphertext, 1), -1);
    ASSUME_ITS_EQUAL_I32(fossil::cryptic::Aes::decrypt(
        plaintext, nullptr, nonce, ad, sizeof(ad), ciphertext, 1), -1);
    ASSUME_ITS_EQUAL_I32(fossil::cryptic::Aes::decrypt(
        plaintext, key, nullptr, ad, sizeof(ad), ciphertext, 1), -1);
    ASSUME_ITS_EQUAL_I32(fossil::cryptic::Aes::decrypt(
        plaintext, key, nonce, nullptr, sizeof(ad), ciphertext, 1), -1);
    ASSUME_ITS_EQUAL_I32(fossil::cryptic::Aes::decrypt(
        plaintext, key, nonce, ad, sizeof(ad), nullptr, 1), -1);
}

FOSSIL_TEST(cpp_test_aes_gcm_decrypt_rejects_modified_tag) {
    const uint8_t key[32] = {0};
    const uint8_t nonce[12] = {0};
    const uint8_t ad[] = {0x01, 0x02};
    const uint8_t plaintext[] = {0x10, 0x20, 0x30};
    uint8_t ciphertext[sizeof(plaintext) + 16];
    uint8_t decrypted[sizeof(plaintext)];

    ASSUME_ITS_EQUAL_I32(fossil::cryptic::Aes::encrypt(
        ciphertext, key, nonce, ad, sizeof(ad), plaintext, sizeof(plaintext)), 0);
    ciphertext[sizeof(plaintext)] ^= 0x01;
    ASSUME_ITS_EQUAL_I32(fossil::cryptic::Aes::decrypt(
        decrypted, key, nonce, ad, sizeof(ad), ciphertext, sizeof(plaintext)), -1);
}


// * * * * * * * * * * * * * * * * * * * * * * * *
// * Fossil Logic Test Pool
// * * * * * * * * * * * * * * * * * * * * * * * *
FOSSIL_TEST_GROUP(cpp_aes_gcm_tests) {
    FOSSIL_ADD_TEST(cpp_aes_fixture, cpp_test_aes_gcm_encrypt_decrypt_roundtrip);
    FOSSIL_ADD_TEST(cpp_aes_fixture, cpp_test_aes_gcm_nist_vector);
    FOSSIL_ADD_TEST(cpp_aes_fixture, cpp_test_aes_gcm_encrypt_null_params);
    FOSSIL_ADD_TEST(cpp_aes_fixture, cpp_test_aes_gcm_decrypt_null_params);
    FOSSIL_ADD_TEST(cpp_aes_fixture, cpp_test_aes_gcm_decrypt_rejects_modified_tag);

    FOSSIL_ADD_SUITE(cpp_aes_fixture);
} // end of tests
