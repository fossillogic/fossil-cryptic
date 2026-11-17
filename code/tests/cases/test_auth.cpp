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
#include <array>
#include <cstdint>


// * * * * * * * * * * * * * * * * * * * * * * * *
// * Fossil Logic Test Utilities
// * * * * * * * * * * * * * * * * * * * * * * * *
// Setup steps for things like test fixtures and
// mock objects are set here.
// * * * * * * * * * * * * * * * * * * * * * * * *

FOSSIL_SUITE(cpp_auth_fixture);

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

FOSSIL_TEST(cpp_test_auth_hmac_sha256) {
    const uint8_t key[] = {'k', 'e', 'y'};
    const char message[] = "The quick brown fox jumps over the lazy dog";
    const std::array<uint8_t, 32> expected = {
        0xf7, 0xbc, 0x83, 0xf4, 0x30, 0x53, 0x84, 0x24,
        0xb1, 0x32, 0x98, 0xe6, 0xaa, 0x6f, 0xb1, 0x43,
        0xef, 0x4d, 0x59, 0xa1, 0x49, 0x46, 0x17, 0x59,
        0x97, 0x47, 0x9d, 0xbc, 0x2d, 0x1a, 0x3c, 0xd8
    };

    const auto actual = fossil::cryptic::Auth::hmac_sha256(
        key, sizeof(key), message, sizeof(message) - 1);
    for (size_t i = 0; i < expected.size(); ++i)
        ASSUME_ITS_TRUE(actual[i] == expected[i]);
}

FOSSIL_TEST(cpp_test_auth_hmac_blake2b_512) {
    const uint8_t key[] = {'k', 'e', 'y'};
    const char message[] = "data";

    const auto first = fossil::cryptic::Auth::hmac_blake2b_512(
        key, sizeof(key), message, sizeof(message) - 1);
    const auto second = fossil::cryptic::Auth::hmac_blake2b_512(
        key, sizeof(key), message, sizeof(message) - 1);

    for (size_t i = 0; i < first.size(); ++i) {
        ASSUME_ITS_TRUE(first[i] == second[i]);
        ASSUME_ITS_TRUE(first[i] != 0);
    }
}


// * * * * * * * * * * * * * * * * * * * * * * * *
// * Fossil Logic Test Pool
// * * * * * * * * * * * * * * * * * * * * * * * *
FOSSIL_TEST_GROUP(cpp_auth_tests) {
    FOSSIL_ADD_TEST(cpp_auth_fixture, cpp_test_auth_hmac_sha256);
    FOSSIL_ADD_TEST(cpp_auth_fixture, cpp_test_auth_hmac_blake2b_512);

    FOSSIL_ADD_SUITE(cpp_auth_fixture);
} // end of tests
