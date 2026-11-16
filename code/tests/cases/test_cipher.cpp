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

FOSSIL_SUITE(cpp_cipher_fixture);

FOSSIL_SETUP(cpp_cipher_fixture) {
    // Setup the test fixture
}

FOSSIL_TEARDOWN(cpp_cipher_fixture) {
    // Teardown the test fixture
}

// * * * * * * * * * * * * * * * * * * * * * * * *
// * Fossil Logic Test Cases
// * * * * * * * * * * * * * * * * * * * * * * * *
// The test cases below are provided as samples, inspired
// by the Meson build system's approach of using test cases
// as samples for library usage.
// * * * * * * * * * * * * * * * * * * * * * * * *

FOSSIL_TEST(cpp_test_cipher_xor_encrypt_decrypt) {
    const std::string key = "K";
    const std::string plaintext = "hello";
    std::string ciphertext(plaintext.size(), '\0');
    std::string decrypted(plaintext.size(), '\0');

    ASSUME_ITS_TRUE(fossil::cryptic::Cipher::xor_cipher(
        reinterpret_cast<const uint8_t *>(key.data()), key.size(),
        reinterpret_cast<const uint8_t *>(plaintext.data()), plaintext.size(),
        reinterpret_cast<uint8_t *>(&ciphertext[0])) == 0);
    ASSUME_ITS_TRUE(fossil::cryptic::Cipher::xor_cipher(
        reinterpret_cast<const uint8_t *>(key.data()), key.size(),
        reinterpret_cast<const uint8_t *>(ciphertext.data()), ciphertext.size(),
        reinterpret_cast<uint8_t *>(&decrypted[0])) == 0);
    ASSUME_ITS_TRUE(memcmp(plaintext.data(), decrypted.data(), plaintext.size()) == 0);
}

FOSSIL_TEST(cpp_test_cipher_invalid_arguments) {
    const uint8_t key[] = {'k'};
    const uint8_t data[] = {'d'};
    uint8_t output[1] = {0};

    ASSUME_ITS_TRUE(fossil::cryptic::Cipher::xor_cipher(nullptr, sizeof(key), data, sizeof(data), output) != 0);
    ASSUME_ITS_TRUE(fossil::cryptic::Cipher::xor_cipher(key, sizeof(key), nullptr, sizeof(data), output) != 0);
    ASSUME_ITS_TRUE(fossil::cryptic::Cipher::xor_cipher(key, sizeof(key), data, sizeof(data), nullptr) != 0);
    ASSUME_ITS_TRUE(fossil::cryptic::Cipher::caesar(1, nullptr, sizeof(data), output) != 0);
    ASSUME_ITS_TRUE(fossil::cryptic::Cipher::caesar(1, data, sizeof(data), nullptr) != 0);
    ASSUME_ITS_TRUE(fossil::cryptic::Cipher::vigenere(nullptr, 1, data, sizeof(data), output) != 0);
    ASSUME_ITS_TRUE(fossil::cryptic::Cipher::vigenere("key", 1, data, sizeof(data), nullptr) != 0);
}

FOSSIL_TEST(cpp_test_cipher_caesar_encrypt_decrypt) {
    const std::string plaintext = "abcXYZ";
    std::string ciphertext(plaintext.size(), '\0');
    std::string decrypted(plaintext.size(), '\0');

    ASSUME_ITS_TRUE(fossil::cryptic::Cipher::caesar(
        3, reinterpret_cast<const uint8_t *>(plaintext.data()), plaintext.size(),
        reinterpret_cast<uint8_t *>(&ciphertext[0])) == 0);
    ASSUME_ITS_TRUE(fossil::cryptic::Cipher::caesar(
        -3, reinterpret_cast<const uint8_t *>(ciphertext.data()), ciphertext.size(),
        reinterpret_cast<uint8_t *>(&decrypted[0])) == 0);
    ASSUME_ITS_TRUE(memcmp(plaintext.data(), decrypted.data(), plaintext.size()) == 0);
}

FOSSIL_TEST(cpp_test_cipher_vigenere_encrypt_decrypt) {
    const std::string key = "LEMON";
    const std::string plaintext = "AttackAtDawn";
    std::string ciphertext(plaintext.size(), '\0');
    std::string decrypted(plaintext.size(), '\0');

    ASSUME_ITS_TRUE(fossil::cryptic::Cipher::vigenere(
        key.c_str(), 1, reinterpret_cast<const uint8_t *>(plaintext.data()), plaintext.size(),
        reinterpret_cast<uint8_t *>(&ciphertext[0])) == 0);
    ASSUME_ITS_TRUE(fossil::cryptic::Cipher::vigenere(
        key.c_str(), 0, reinterpret_cast<const uint8_t *>(ciphertext.data()), ciphertext.size(),
        reinterpret_cast<uint8_t *>(&decrypted[0])) == 0);
    ASSUME_ITS_TRUE(memcmp(plaintext.data(), decrypted.data(), plaintext.size()) == 0);
}

// * * * * * * * * * * * * * * * * * * * * * * * *
// * Fossil Logic Test Pool
// * * * * * * * * * * * * * * * * * * * * * * * *
FOSSIL_TEST_GROUP(cpp_cipher_tests) {
    FOSSIL_ADD_TEST(cpp_cipher_fixture, cpp_test_cipher_xor_encrypt_decrypt);
    FOSSIL_ADD_TEST(cpp_cipher_fixture, cpp_test_cipher_invalid_arguments);
    FOSSIL_ADD_TEST(cpp_cipher_fixture, cpp_test_cipher_caesar_encrypt_decrypt);
    FOSSIL_ADD_TEST(cpp_cipher_fixture, cpp_test_cipher_vigenere_encrypt_decrypt);

    FOSSIL_ADD_SUITE(cpp_cipher_fixture);
} // end of tests
