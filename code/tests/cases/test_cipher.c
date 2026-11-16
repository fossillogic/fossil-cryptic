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

FOSSIL_SUITE(c_cipher_fixture);

FOSSIL_SETUP(c_cipher_fixture) {
    // Setup the test fixture
}

FOSSIL_TEARDOWN(c_cipher_fixture) {
    // Teardown the test fixture
}

// * * * * * * * * * * * * * * * * * * * * * * * *
// * Fossil Logic Test Cases
// * * * * * * * * * * * * * * * * * * * * * * * *
// The test cases below are provided as samples, inspired
// by the Meson build system's approach of using test cases
// as samples for library usage.
// * * * * * * * * * * * * * * * * * * * * * * * *

FOSSIL_TEST(c_test_cipher_xor) {
    const uint8_t key[] = {'K'};
    const uint8_t plaintext[] = "hello";
    const uint8_t expected[] = {0x23, 0x2e, 0x27, 0x27, 0x24};
    uint8_t ciphertext[sizeof(plaintext) - 1];
    uint8_t decrypted[sizeof(plaintext) - 1];
    const size_t input_len = sizeof(plaintext) - 1;

    int rc = fossil_cryptic_cipher_xor(key, sizeof(key), plaintext, input_len, ciphertext);
    ASSUME_ITS_EQUAL_I32(rc, 0);
    ASSUME_ITS_TRUE(memcmp(ciphertext, expected, input_len) == 0);

    rc = fossil_cryptic_cipher_xor(key, sizeof(key), ciphertext, input_len, decrypted);
    ASSUME_ITS_EQUAL_I32(rc, 0);
    ASSUME_ITS_TRUE(memcmp(plaintext, decrypted, input_len) == 0);
}

FOSSIL_TEST(c_test_cipher_caesar) {
    const uint8_t plaintext[] = "abcXYZ, 123";
    const uint8_t expected[] = "defABC, 123";
    uint8_t ciphertext[sizeof(plaintext)];
    uint8_t decrypted[sizeof(plaintext)];
    const size_t input_len = sizeof(plaintext) - 1;

    int rc = fossil_cryptic_cipher_caesar(3, plaintext, input_len, ciphertext);
    ASSUME_ITS_EQUAL_I32(rc, 0);
    ASSUME_ITS_TRUE(memcmp(ciphertext, expected, input_len) == 0);

    rc = fossil_cryptic_cipher_caesar(-3, ciphertext, input_len, decrypted);
    ASSUME_ITS_EQUAL_I32(rc, 0);
    ASSUME_ITS_TRUE(memcmp(plaintext, decrypted, input_len) == 0);
}

FOSSIL_TEST(c_test_cipher_vigenere) {
    const char *key = "LEMON";
    const uint8_t plaintext[] = "ATTACKATDAWN";
    const uint8_t expected[] = "LXFOPVEFRNHR";
    uint8_t ciphertext[sizeof(plaintext)];
    uint8_t decrypted[sizeof(plaintext)];
    const size_t input_len = sizeof(plaintext) - 1;

    int rc = fossil_cryptic_cipher_vigenere(key, 1, plaintext, input_len, ciphertext);
    ASSUME_ITS_EQUAL_I32(rc, 0);
    ASSUME_ITS_TRUE(memcmp(ciphertext, expected, input_len) == 0);

    rc = fossil_cryptic_cipher_vigenere(key, 0, ciphertext, input_len, decrypted);
    ASSUME_ITS_EQUAL_I32(rc, 0);
    ASSUME_ITS_TRUE(memcmp(plaintext, decrypted, input_len) == 0);
}

// * * * * * * * * * * * * * * * * * * * * * * * *
// * Fossil Logic Test Pool
// * * * * * * * * * * * * * * * * * * * * * * * *
FOSSIL_TEST_GROUP(c_cipher_tests) {
    FOSSIL_ADD_TEST(c_cipher_fixture, c_test_cipher_xor);
    FOSSIL_ADD_TEST(c_cipher_fixture, c_test_cipher_caesar);
    FOSSIL_ADD_TEST(c_cipher_fixture, c_test_cipher_vigenere);

    FOSSIL_ADD_SUITE(c_cipher_fixture);
} // end of tests
