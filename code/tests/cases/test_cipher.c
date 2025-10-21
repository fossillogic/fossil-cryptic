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
 * Date: 04/05/2014
 *
 * Copyright (C) 2014-2025 Fossil Logic. All rights reserved.
 * -----------------------------------------------------------------------------
 */
#include <fossil/pizza/framework.h>
#include "fossil/cryptic/framework.h"


// * * * * * * * * * * * * * * * * * * * * * * * *
// * Fossil Logic Test Utilities
// * * * * * * * * * * * * * * * * * * * * * * * *
// Setup steps for things like test fixtures and
// mock objects are set here.
// * * * * * * * * * * * * * * * * * * * * * * * *

FOSSIL_TEST_SUITE(c_cipher_fixture);

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

FOSSIL_TEST_CASE(c_test_cipher_compute_basic_xor_encrypt_decrypt) {
    // Basic XOR cipher encryption and decryption
    const char *algorithm = "xor";
    const char *mode_enc = "encrypt";
    const char *mode_dec = "decrypt";
    const char *bits = "u8";
    const char *key = "K";
    const char *plaintext = "hello";
    size_t input_len = strlen(plaintext);
    unsigned char ciphertext[64];
    size_t ciphertext_len = sizeof(ciphertext);

    int rc = fossil_cryptic_cipher_compute(
        algorithm, mode_enc, bits, key,
        plaintext, input_len,
        ciphertext, &ciphertext_len
    );
    ASSUME_ITS_EQUAL_I32(rc, 0);
    ASSUME_ITS_TRUE(ciphertext_len == input_len);

    char decrypted[64];
    size_t decrypted_len = sizeof(decrypted);
    rc = fossil_cryptic_cipher_compute(
        algorithm, mode_dec, bits, key,
        ciphertext, ciphertext_len,
        decrypted, &decrypted_len
    );
    ASSUME_ITS_EQUAL_I32(rc, 0);
    ASSUME_ITS_TRUE(decrypted_len == input_len);
    ASSUME_ITS_TRUE(memcmp(plaintext, decrypted, input_len) == 0);
}

FOSSIL_TEST_CASE(c_test_cipher_compute_null_arguments) {
    // Should fail with null arguments
    char out[32];
    size_t out_len = sizeof(out);
    int rc = fossil_cryptic_cipher_compute(NULL, "encrypt", "u8", "key", "data", 4, out, &out_len);
    ASSUME_ITS_TRUE(rc != 0);

    rc = fossil_cryptic_cipher_compute("xor", NULL, "u8", "key", "data", 4, out, &out_len);
    ASSUME_ITS_TRUE(rc != 0);

    rc = fossil_cryptic_cipher_compute("xor", "encrypt", NULL, "key", "data", 4, out, &out_len);
    ASSUME_ITS_TRUE(rc != 0);

    rc = fossil_cryptic_cipher_compute("xor", "encrypt", "u8", NULL, "data", 4, out, &out_len);
    ASSUME_ITS_TRUE(rc != 0);

    rc = fossil_cryptic_cipher_compute("xor", "encrypt", "u8", "key", NULL, 4, out, &out_len);
    ASSUME_ITS_TRUE(rc != 0);

    rc = fossil_cryptic_cipher_compute("xor", "encrypt", "u8", "key", "data", 4, NULL, &out_len);
    ASSUME_ITS_TRUE(rc != 0);

    rc = fossil_cryptic_cipher_compute("xor", "encrypt", "u8", "key", "data", 4, out, NULL);
    ASSUME_ITS_TRUE(rc != 0);
}

FOSSIL_TEST_CASE(c_test_cipher_compute_unsupported_algorithm) {
    // Should fail with unsupported algorithm
    char out[32];
    size_t out_len = sizeof(out);
    int rc = fossil_cryptic_cipher_compute("unknown", "encrypt", "u8", "key", "data", 4, out, &out_len);
    ASSUME_ITS_TRUE(rc == 0);
    // Optionally, check that output length is zero or unchanged if needed
}

FOSSIL_TEST_CASE(c_test_cipher_compute_caesar_encrypt_decrypt) {
    // Caesar cipher encryption and decryption
    const char *algorithm = "caesar";
    const char *mode_enc = "encrypt";
    const char *mode_dec = "decrypt";
    const char *bits = "u8";
    const char *key = "3";
    const char *plaintext = "abcXYZ";
    size_t input_len = strlen(plaintext);
    char ciphertext[64];
    size_t ciphertext_len = sizeof(ciphertext);

    int rc = fossil_cryptic_cipher_compute(
        algorithm, mode_enc, bits, key,
        plaintext, input_len,
        ciphertext, &ciphertext_len
    );
    ASSUME_ITS_EQUAL_I32(rc, 0);

    char decrypted[64];
    size_t decrypted_len = sizeof(decrypted);
    rc = fossil_cryptic_cipher_compute(
        algorithm, mode_dec, bits, key,
        ciphertext, ciphertext_len,
        decrypted, &decrypted_len
    );
    ASSUME_ITS_EQUAL_I32(rc, 0);
    ASSUME_ITS_TRUE(decrypted_len == input_len);
    ASSUME_ITS_TRUE(memcmp(plaintext, decrypted, input_len) == 0);
}

// * * * * * * * * * * * * * * * * * * * * * * * *
// * Fossil Logic Test Pool
// * * * * * * * * * * * * * * * * * * * * * * * *
FOSSIL_TEST_GROUP(c_cipher_tests) {
    FOSSIL_TEST_ADD(c_cipher_fixture, c_test_cipher_compute_basic_xor_encrypt_decrypt);
    FOSSIL_TEST_ADD(c_cipher_fixture, c_test_cipher_compute_null_arguments);
    FOSSIL_TEST_ADD(c_cipher_fixture, c_test_cipher_compute_unsupported_algorithm);
    FOSSIL_TEST_ADD(c_cipher_fixture, c_test_cipher_compute_caesar_encrypt_decrypt);

    FOSSIL_TEST_REGISTER(c_cipher_fixture);
} // end of tests
