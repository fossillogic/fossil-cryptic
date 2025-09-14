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

FOSSIL_TEST_SUITE(cpp_auth_fixture);

FOSSIL_SETUP(cpp_auth_fixture) {
    // Setup the test fixture
}

FOSSIL_TEARDOWN(cpp_auth_fixture) {
    // Teardown the test fixture
}

// * * * * * * * * * * * * * * * * * * * * * * * *
// * Fossil Logic Test Cases
// * * * * * * * * * * * * * * * * * * * * * * * *
// The test cases below are provided as samples, inspired
// by the Meson build system's approach of using test cases
// as samples for library usage.
// * * * * * * * * * * * * * * * * * * * * * * * *

FOSSIL_TEST_CASE(cpp_test_hmac_sha256_known_vector) {
    // Test vector from RFC 4231 Test Case 1
    const uint8_t key[20] = {
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b
    };
    const uint8_t data[] = "Hi There";
    auto mac = fossil::cryptic::Auth::hmac_sha256(key, sizeof(key), data, sizeof(data) - 1);
    std::string hex = fossil::cryptic::Hash::to_hex(mac);
    ASSUME_ITS_EQUAL_CSTR(
        hex.c_str(),
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    );
}

FOSSIL_TEST_CASE(cpp_test_hmac_sha256_empty_key_data) {
    // HMAC-SHA256 with empty key and data
    auto mac = fossil::cryptic::Auth::hmac_sha256(nullptr, 0, nullptr, 0);
    std::string hex = fossil::cryptic::Hash::to_hex(mac);
    // Precomputed with OpenSSL: HMAC_SHA256("", "") = b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad
    ASSUME_ITS_EQUAL_CSTR(
        hex.c_str(),
        "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad"
    );
}

FOSSIL_TEST_CASE(cpp_test_pbkdf2_sha256_known_vector) {
    // Test vector from RFC 6070 (adapted for SHA256)
    const char *password = "password";
    const uint8_t salt[] = "salt";
    uint32_t iterations = 1;
    size_t dklen = 32;
    auto dk = fossil::cryptic::Auth::pbkdf2_sha256(
        reinterpret_cast<const uint8_t*>(password), strlen(password),
        salt, sizeof(salt) - 1,
        iterations, dklen
    );
    std::string hex = fossil::cryptic::Hash::to_hex(dk);
    // Precomputed with OpenSSL: pbkdf2_sha256("password", "salt", 1, 32)
    ASSUME_ITS_EQUAL_CSTR(
        hex.c_str(),
        "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"
    );
}

FOSSIL_TEST_CASE(cpp_test_pbkdf2_sha256_empty_password_salt) {
    // PBKDF2-SHA256 with empty password and salt
    uint32_t iterations = 1;
    size_t dklen = 32;
    auto dk = fossil::cryptic::Auth::pbkdf2_sha256(
        nullptr, 0, nullptr, 0, iterations, dklen
    );
    std::string hex = fossil::cryptic::Hash::to_hex(dk);
    // Precomputed with OpenSSL: pbkdf2_sha256("", "", 1, 32)
    ASSUME_ITS_EQUAL_CSTR(
        hex.c_str(),
        "f7ce0b653d2d72a4108cf5abe912ffdd777616dbbb27a70e8204f3ae2d0f6fad"
    );
}

// * * * * * * * * * * * * * * * * * * * * * * * *
// * Fossil Logic Test Pool
// * * * * * * * * * * * * * * * * * * * * * * * *
FOSSIL_TEST_GROUP(cpp_auth_tests) {
    FOSSIL_TEST_ADD(cpp_auth_fixture, cpp_test_hmac_sha256_known_vector);
    FOSSIL_TEST_ADD(cpp_auth_fixture, cpp_test_hmac_sha256_empty_key_data);
    FOSSIL_TEST_ADD(cpp_auth_fixture, cpp_test_pbkdf2_sha256_known_vector);
    FOSSIL_TEST_ADD(cpp_auth_fixture, cpp_test_pbkdf2_sha256_empty_password_salt);

    FOSSIL_TEST_REGISTER(cpp_auth_fixture);
} // end of tests
