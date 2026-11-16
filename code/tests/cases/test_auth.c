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

FOSSIL_SUITE(c_auth_fixture);

FOSSIL_SETUP(c_auth_fixture) {
    // Setup the test fixture
}

FOSSIL_TEARDOWN(c_auth_fixture) {
    // Teardown the test fixture
}

// * * * * * * * * * * * * * * * * * * * * * * * *
// * Fossil Logic Test Cases
// * * * * * * * * * * * * * * * * * * * * * * * *
// The test cases below are provided as samples, inspired
// by the Meson build system's approach of using test cases
// as samples for library usage.
// * * * * * * * * * * * * * * * * * * * * * * * *

FOSSIL_TEST(c_test_auth_hmac_sha256_rfc4231_case1) {
    const uint8_t key[20] = {
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b
    };
    const char message[] = "Hi There";
    const uint8_t expected[32] = {
        0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53,
        0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b,
        0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7,
        0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7
    };
    uint8_t output[32];
    size_t i;

    ASSUME_ITS_EQUAL_I32(
        fossil_cryptic_auth_hmac_sha256(key, sizeof(key), message, sizeof(message) - 1, output),
        0
    );
    for (i = 0; i < sizeof(output); ++i) {
        ASSUME_ITS_EQUAL_I32(output[i], expected[i]);
    }
}

FOSSIL_TEST(c_test_auth_hmac_sha256_null_params) {
    const uint8_t key[] = { 0x01 };
    const char message[] = "data";
    uint8_t output[32];

    ASSUME_ITS_TRUE(fossil_cryptic_auth_hmac_sha256(NULL, sizeof(key), message, sizeof(message) - 1, output) != 0);
    ASSUME_ITS_TRUE(fossil_cryptic_auth_hmac_sha256(key, sizeof(key), NULL, sizeof(message) - 1, output) != 0);
    ASSUME_ITS_TRUE(fossil_cryptic_auth_hmac_sha256(key, sizeof(key), message, sizeof(message) - 1, NULL) != 0);
}

FOSSIL_TEST(c_test_auth_hmac_blake2b_512) {
    const uint8_t key[] = { 0x01, 0x02, 0x03, 0x04 };
    const char message[] = "authentication test";
    const char other_message[] = "different message";
    uint8_t output[64];
    uint8_t repeated[64];
    uint8_t changed[64];
    size_t i;
    int outputs_match = 1;
    int changed_output_matches = 1;

    ASSUME_ITS_EQUAL_I32(
        fossil_cryptic_auth_hmac_blake2b_512(key, sizeof(key), message, sizeof(message) - 1, output),
        0
    );
    ASSUME_ITS_EQUAL_I32(
        fossil_cryptic_auth_hmac_blake2b_512(key, sizeof(key), message, sizeof(message) - 1, repeated),
        0
    );
    ASSUME_ITS_EQUAL_I32(
        fossil_cryptic_auth_hmac_blake2b_512(key, sizeof(key), other_message, sizeof(other_message) - 1, changed),
        0
    );

    for (i = 0; i < sizeof(output); ++i) {
        if (output[i] != repeated[i]) outputs_match = 0;
        if (output[i] != changed[i]) changed_output_matches = 0;
    }
    ASSUME_ITS_TRUE(outputs_match);
    ASSUME_ITS_TRUE(!changed_output_matches);
}

FOSSIL_TEST(c_test_auth_hmac_blake2b_512_null_params) {
    const uint8_t key[] = { 0x01 };
    const char message[] = "data";
    uint8_t output[64];

    ASSUME_ITS_TRUE(fossil_cryptic_auth_hmac_blake2b_512(NULL, sizeof(key), message, sizeof(message) - 1, output) != 0);
    ASSUME_ITS_TRUE(fossil_cryptic_auth_hmac_blake2b_512(key, sizeof(key), NULL, sizeof(message) - 1, output) != 0);
    ASSUME_ITS_TRUE(fossil_cryptic_auth_hmac_blake2b_512(key, sizeof(key), message, sizeof(message) - 1, NULL) != 0);
}


// * * * * * * * * * * * * * * * * * * * * * * * *
// * Fossil Logic Test Pool
// * * * * * * * * * * * * * * * * * * * * * * * *
FOSSIL_TEST_GROUP(c_auth_tests) {
    FOSSIL_ADD_TEST(c_auth_fixture, c_test_auth_hmac_sha256_rfc4231_case1);
    FOSSIL_ADD_TEST(c_auth_fixture, c_test_auth_hmac_sha256_null_params);
    FOSSIL_ADD_TEST(c_auth_fixture, c_test_auth_hmac_blake2b_512);
    FOSSIL_ADD_TEST(c_auth_fixture, c_test_auth_hmac_blake2b_512_null_params);

    FOSSIL_ADD_SUITE(c_auth_fixture);
} // end of tests
