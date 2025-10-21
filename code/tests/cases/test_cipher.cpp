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

FOSSIL_TEST_SUITE(cpp_cipher_fixture);

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

FOSSIL_TEST_CASE(cpp_test_cipher_compute_basicpp_xor_encrypt_decrypt) {
    // Basic XOR cipher encryption and decryption using fossil::cryptic::Cipher
    const std::string algorithm = "xor";
    const std::string mode_enc = "encrypt";
    const std::string mode_dec = "decrypt";
    const std::string bits = "u8";
    const std::string key = "K";
    const std::string plaintext = "hello";

    auto ciphertext = fossil::cryptic::Cipher::compute(
        algorithm, mode_enc, bits, key, plaintext
    );
    ASSUME_ITS_TRUE(ciphertext.size() == plaintext.size());

    auto decrypted = fossil::cryptic::Cipher::compute(
        algorithm, mode_dec, bits, key, ciphertext
    );
    ASSUME_ITS_TRUE(decrypted.size() == plaintext.size());
    ASSUME_ITS_TRUE(memcmp(plaintext.data(), decrypted.data(), plaintext.size()) == 0);
}

FOSSIL_TEST_CASE(cpp_test_cipher_compute_null_arguments) {
    // Should fail with null arguments using fossil::cryptic::Cipher
    const std::string bits = "u8";
    const std::string key = "key";
    const std::string data = "data";

    auto out1 = fossil::cryptic::Cipher::compute("", "encrypt", bits, key, data);
    ASSUME_ITS_TRUE(out1.empty());

    auto out2 = fossil::cryptic::Cipher::compute("xor", "", bits, key, data);
    ASSUME_ITS_TRUE(out2.empty());

    auto out3 = fossil::cryptic::Cipher::compute("xor", "encrypt", "", key, data);
    ASSUME_ITS_TRUE(out3.empty());

    auto out4 = fossil::cryptic::Cipher::compute("xor", "encrypt", bits, "", data);
    ASSUME_ITS_TRUE(out4.empty());

    auto out5 = fossil::cryptic::Cipher::compute("xor", "encrypt", bits, key, "");
    ASSUME_ITS_TRUE(out5.empty());
}

FOSSIL_TEST_CASE(cpp_test_cipher_compute_unsupported_algorithm) {
    // Should fail with unsupported algorithm using fossil::cryptic::Cipher
    const std::string algorithm = "unknown";
    const std::string mode = "encrypt";
    const std::string bits = "u8";
    const std::string key = "key";
    const std::string data = "data";

    bool exception_thrown = false;
    try {
        auto out = fossil::cryptic::Cipher::compute(algorithm, mode, bits, key, data);
    } catch (const std::exception&) {
        exception_thrown = true;
    }
    ASSUME_ITS_TRUE(exception_thrown);
}

FOSSIL_TEST_CASE(cpp_test_cipher_compute_caesar_encrypt_decrypt) {
    // Caesar cipher encryption and decryption using fossil::cryptic::Cipher
    const std::string algorithm = "caesar";
    const std::string mode_enc = "encrypt";
    const std::string mode_dec = "decrypt";
    const std::string bits = "u8";
    const std::string key = "3";
    const std::string plaintext = "abcXYZ";

    auto ciphertext = fossil::cryptic::Cipher::compute(
        algorithm, mode_enc, bits, key, plaintext
    );

    auto decrypted = fossil::cryptic::Cipher::compute(
        algorithm, mode_dec, bits, key, ciphertext
    );
    ASSUME_ITS_TRUE(decrypted.size() == plaintext.size());
    ASSUME_ITS_TRUE(memcmp(plaintext.data(), decrypted.data(), plaintext.size()) == 0);
}

// * * * * * * * * * * * * * * * * * * * * * * * *
// * Fossil Logic Test Pool
// * * * * * * * * * * * * * * * * * * * * * * * *
FOSSIL_TEST_GROUP(cpp_cipher_tests) {
    FOSSIL_TEST_ADD(cpp_cipher_fixture, cpp_test_cipher_compute_basicpp_xor_encrypt_decrypt);
    FOSSIL_TEST_ADD(cpp_cipher_fixture, cpp_test_cipher_compute_null_arguments);
    FOSSIL_TEST_ADD(cpp_cipher_fixture, cpp_test_cipher_compute_unsupported_algorithm);
    FOSSIL_TEST_ADD(cpp_cipher_fixture, cpp_test_cipher_compute_caesar_encrypt_decrypt);

    FOSSIL_TEST_REGISTER(cpp_cipher_fixture);
} // end of tests
