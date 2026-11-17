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

FOSSIL_SUITE(cpp_chacha_fixture);

FOSSIL_SETUP(cpp_chacha_fixture) {
    // Setup the test fixture
}

FOSSIL_TEARDOWN(cpp_chacha_fixture) {
    // Teardown the test fixture
}

// * * * * * * * * * * * * * * * * * * * * * * * *
// * Fossil Logic Test Cases
// * * * * * * * * * * * * * * * * * * * * * * * *
// The test cases below are provided as samples, inspired
// by the Meson build system's approach of using test cases
// as samples for library usage.
// * * * * * * * * * * * * * * * * * * * * * * * *

FOSSIL_TEST(cpp_test_chacha20_xor_roundtrip) {
    const uint8_t key[32] = {0};
    const uint8_t nonce[12] = {0};
    const uint8_t plaintext[] = {0x10, 0x20, 0x30, 0x40, 0x50};
    uint8_t ciphertext[sizeof(plaintext)];
    uint8_t decrypted[sizeof(plaintext)];

    ASSUME_ITS_EQUAL_I32(fossil::cryptic::Chacha::xor_stream(
        ciphertext, plaintext, sizeof(plaintext), key, nonce, 0), 0);
    ASSUME_ITS_EQUAL_I32(fossil::cryptic::Chacha::xor_stream(
        decrypted, ciphertext, sizeof(ciphertext), key, nonce, 0), 0);
    ASSUME_ITS_TRUE(memcmp(decrypted, plaintext, sizeof(plaintext)) == 0);
}

FOSSIL_TEST(cpp_test_chacha20_xor_known_vector) {
    const uint8_t key[32] = {0};
    const uint8_t nonce[12] = {0};
    const uint8_t input = 0;
    uint8_t output = 0;

    ASSUME_ITS_EQUAL_I32(fossil::cryptic::Chacha::xor_stream(
        &output, &input, 1, key, nonce, 0), 0);
    ASSUME_ITS_EQUAL_I32(output, 0x76);
}

FOSSIL_TEST(cpp_test_chacha20_xor_null_params) {
    const uint8_t key[32] = {0};
    const uint8_t nonce[12] = {0};
    const uint8_t input = 0;
    uint8_t output = 0;

    ASSUME_ITS_TRUE(fossil::cryptic::Chacha::xor_stream(
        NULL, &input, 1, key, nonce, 0) != 0);
    ASSUME_ITS_TRUE(fossil::cryptic::Chacha::xor_stream(
        &output, NULL, 1, key, nonce, 0) != 0);
    ASSUME_ITS_TRUE(fossil::cryptic::Chacha::xor_stream(
        &output, &input, 1, NULL, nonce, 0) != 0);
    ASSUME_ITS_TRUE(fossil::cryptic::Chacha::xor_stream(
        &output, &input, 1, key, NULL, 0) != 0);
}

FOSSIL_TEST(cpp_test_poly1305_rfc_vector) {
    const uint8_t key[32] = {
        0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33,
        0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06, 0xa8,
        0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd,
        0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49, 0xf5, 0x1b
    };
    const uint8_t message[] = "Cryptographic Forum Research Group";
    const uint8_t expected[16] = {
        0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6,
        0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01, 0x27, 0xa9
    };
    uint8_t tag[16];

    ASSUME_ITS_EQUAL_I32(fossil::cryptic::Chacha::poly1305(
        tag, message, sizeof(message) - 1, key), 0);
    ASSUME_ITS_TRUE(memcmp(tag, expected, sizeof(expected)) == 0);
}

FOSSIL_TEST(cpp_test_poly1305_null_params) {
    const uint8_t key[32] = {0};
    const uint8_t message[] = {0x01};
    uint8_t tag[16];

    ASSUME_ITS_TRUE(fossil::cryptic::Chacha::poly1305(NULL, message, sizeof(message), key) != 0);
    ASSUME_ITS_TRUE(fossil::cryptic::Chacha::poly1305(tag, NULL, sizeof(message), key) != 0);
    ASSUME_ITS_TRUE(fossil::cryptic::Chacha::poly1305(tag, message, sizeof(message), NULL) != 0);
}

FOSSIL_TEST(cpp_test_chacha20_poly1305_encrypt_decrypt_roundtrip) {
    const uint8_t key[32] = {0};
    const uint8_t nonce[12] = {0};
    const uint8_t ad[] = {0x01, 0x02, 0x03};
    const uint8_t plaintext[] = {0x10, 0x20, 0x30, 0x40, 0x50};
    uint8_t ciphertext[sizeof(plaintext) + 16];
    uint8_t decrypted[sizeof(plaintext)];

    ASSUME_ITS_EQUAL_I32(fossil::cryptic::Chacha::encrypt(
        ciphertext, key, nonce, ad, sizeof(ad), plaintext, sizeof(plaintext)), 0);
    ASSUME_ITS_EQUAL_I32(fossil::cryptic::Chacha::decrypt(
        decrypted, key, nonce, ad, sizeof(ad), ciphertext, sizeof(ciphertext)), 0);
    ASSUME_ITS_TRUE(memcmp(decrypted, plaintext, sizeof(plaintext)) == 0);
}

FOSSIL_TEST(cpp_test_chacha20_poly1305_encrypt_null_params) {
    const uint8_t key[32] = {0};
    const uint8_t nonce[12] = {0};
    const uint8_t ad[] = {0x01};
    const uint8_t plaintext[] = {0x02};
    uint8_t ciphertext[sizeof(plaintext) + 16];

    ASSUME_ITS_EQUAL_I32(fossil::cryptic::Chacha::encrypt(
        NULL, key, nonce, ad, sizeof(ad), plaintext, sizeof(plaintext)), -1);
    ASSUME_ITS_EQUAL_I32(fossil::cryptic::Chacha::encrypt(
        ciphertext, NULL, nonce, ad, sizeof(ad), plaintext, sizeof(plaintext)), -1);
    ASSUME_ITS_EQUAL_I32(fossil::cryptic::Chacha::encrypt(
        ciphertext, key, NULL, ad, sizeof(ad), plaintext, sizeof(plaintext)), -1);
    ASSUME_ITS_EQUAL_I32(fossil::cryptic::Chacha::encrypt(
        ciphertext, key, nonce, NULL, sizeof(ad), plaintext, sizeof(plaintext)), -1);
    ASSUME_ITS_EQUAL_I32(fossil::cryptic::Chacha::encrypt(
        ciphertext, key, nonce, ad, sizeof(ad), NULL, sizeof(plaintext)), -1);
}

FOSSIL_TEST(cpp_test_chacha20_poly1305_decrypt_null_params) {
    const uint8_t key[32] = {0};
    const uint8_t nonce[12] = {0};
    const uint8_t ad[] = {0x01};
    const uint8_t ciphertext[17] = {0};
    uint8_t plaintext[1];

    ASSUME_ITS_EQUAL_I32(fossil::cryptic::Chacha::decrypt(
        NULL, key, nonce, ad, sizeof(ad), ciphertext, sizeof(ciphertext)), -1);
    ASSUME_ITS_EQUAL_I32(fossil::cryptic::Chacha::decrypt(
        plaintext, NULL, nonce, ad, sizeof(ad), ciphertext, sizeof(ciphertext)), -1);
    ASSUME_ITS_EQUAL_I32(fossil::cryptic::Chacha::decrypt(
        plaintext, key, NULL, ad, sizeof(ad), ciphertext, sizeof(ciphertext)), -1);
    ASSUME_ITS_EQUAL_I32(fossil::cryptic::Chacha::decrypt(
        plaintext, key, nonce, NULL, sizeof(ad), ciphertext, sizeof(ciphertext)), -1);
    ASSUME_ITS_EQUAL_I32(fossil::cryptic::Chacha::decrypt(
        plaintext, key, nonce, ad, sizeof(ad), NULL, sizeof(ciphertext)), -1);
}

FOSSIL_TEST(cpp_test_chacha20_poly1305_decrypt_rejects_modified_ciphertext) {
    const uint8_t key[32] = {0};
    const uint8_t nonce[12] = {0};
    const uint8_t ad[] = {0x01, 0x02};
    const uint8_t plaintext[] = {0x10, 0x20, 0x30};
    uint8_t ciphertext[sizeof(plaintext) + 16];
    uint8_t decrypted[sizeof(plaintext)];

    ASSUME_ITS_EQUAL_I32(fossil::cryptic::Chacha::encrypt(
        ciphertext, key, nonce, ad, sizeof(ad), plaintext, sizeof(plaintext)), 0);
    ciphertext[0] ^= 0x01;
    ASSUME_ITS_EQUAL_I32(fossil::cryptic::Chacha::decrypt(
        decrypted, key, nonce, ad, sizeof(ad), ciphertext, sizeof(ciphertext)), -1);
}

FOSSIL_TEST(cpp_test_chacha20_poly1305_decrypt_rejects_modified_tag) {
    const uint8_t key[32] = {0};
    const uint8_t nonce[12] = {0};
    const uint8_t ad[] = {0x01, 0x02};
    const uint8_t plaintext[] = {0x10, 0x20, 0x30};
    uint8_t ciphertext[sizeof(plaintext) + 16];
    uint8_t decrypted[sizeof(plaintext)];

    ASSUME_ITS_EQUAL_I32(fossil::cryptic::Chacha::encrypt(
        ciphertext, key, nonce, ad, sizeof(ad), plaintext, sizeof(plaintext)), 0);
    ciphertext[sizeof(plaintext)] ^= 0x01;
    ASSUME_ITS_EQUAL_I32(fossil::cryptic::Chacha::decrypt(
        decrypted, key, nonce, ad, sizeof(ad), ciphertext, sizeof(ciphertext)), -1);
}

FOSSIL_TEST(cpp_test_chacha20_poly1305_decrypt_rejects_modified_aad) {
    const uint8_t key[32] = {0};
    const uint8_t nonce[12] = {0};
    const uint8_t ad[] = {0x01, 0x02};
    const uint8_t modified_ad[] = {0x01, 0x03};
    const uint8_t plaintext[] = {0x10, 0x20, 0x30};
    uint8_t ciphertext[sizeof(plaintext) + 16];
    uint8_t decrypted[sizeof(plaintext)];

    ASSUME_ITS_EQUAL_I32(fossil::cryptic::Chacha::encrypt(
        ciphertext, key, nonce, ad, sizeof(ad), plaintext, sizeof(plaintext)), 0);
    ASSUME_ITS_EQUAL_I32(fossil::cryptic::Chacha::decrypt(
        decrypted, key, nonce, modified_ad, sizeof(modified_ad),
        ciphertext, sizeof(ciphertext)), -1);
}

// * * * * * * * * * * * * * * * * * * * * * * * *
// * Fossil Logic Test Pool
// * * * * * * * * * * * * * * * * * * * * * * * *
FOSSIL_TEST_GROUP(cpp_chacha_tests) {
    FOSSIL_ADD_TEST(cpp_chacha_fixture, cpp_test_chacha20_xor_roundtrip);
    FOSSIL_ADD_TEST(cpp_chacha_fixture, cpp_test_chacha20_xor_known_vector);
    FOSSIL_ADD_TEST(cpp_chacha_fixture, cpp_test_chacha20_xor_null_params);
    FOSSIL_ADD_TEST(cpp_chacha_fixture, cpp_test_poly1305_rfc_vector);
    FOSSIL_ADD_TEST(cpp_chacha_fixture, cpp_test_poly1305_null_params);
    FOSSIL_ADD_TEST(cpp_chacha_fixture, cpp_test_chacha20_poly1305_encrypt_decrypt_roundtrip);
    FOSSIL_ADD_TEST(cpp_chacha_fixture, cpp_test_chacha20_poly1305_encrypt_null_params);
    FOSSIL_ADD_TEST(cpp_chacha_fixture, cpp_test_chacha20_poly1305_decrypt_null_params);
    FOSSIL_ADD_TEST(cpp_chacha_fixture, cpp_test_chacha20_poly1305_decrypt_rejects_modified_ciphertext);
    FOSSIL_ADD_TEST(cpp_chacha_fixture, cpp_test_chacha20_poly1305_decrypt_rejects_modified_tag);
    FOSSIL_ADD_TEST(cpp_chacha_fixture, cpp_test_chacha20_poly1305_decrypt_rejects_modified_aad);

    FOSSIL_ADD_SUITE(cpp_chacha_fixture);
} // end of tests
