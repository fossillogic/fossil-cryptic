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

FOSSIL_SUITE(c_keygen_fixture);

FOSSIL_SETUP(c_keygen_fixture) {
    // Setup the test fixture
}

FOSSIL_TEARDOWN(c_keygen_fixture) {
    // Teardown the test fixture
}

// * * * * * * * * * * * * * * * * * * * * * * * *
// * Fossil Logic Test Cases
// * * * * * * * * * * * * * * * * * * * * * * * *
// The test cases below are provided as samples, inspired
// by the Meson build system's approach of using test cases
// as samples for library usage.
// * * * * * * * * * * * * * * * * * * * * * * * *

FOSSIL_TEST(c_test_keygen_hkdf_sha256_rfc5869) {
    // RFC 5869 test case 1
    const uint8_t ikm[22] = {
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b
    };
    const uint8_t salt[13] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
        0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c
    };
    const uint8_t info[10] = {
        0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9
    };
    const uint8_t expected[42] = {
        0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a,
        0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a,
        0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c,
        0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf,
        0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18,
        0x58, 0x65
    };
    uint8_t output[sizeof(expected)];
    int rc = fossil_cryptic_keygen_hkdf_sha256(
        ikm, sizeof(ikm), salt, sizeof(salt), info, sizeof(info), output, sizeof(output));
    ASSUME_ITS_EQUAL_I32(rc, 0);
    ASSUME_ITS_TRUE(memcmp(output, expected, sizeof(expected)) == 0);
}

FOSSIL_TEST(c_test_keygen_hkdf_sha256_optional_salt_info) {
    const uint8_t ikm[] = {0x01, 0x02, 0x03, 0x04};
    uint8_t output[32];
    int rc = fossil_cryptic_keygen_hkdf_sha256(
        ikm, sizeof(ikm), NULL, 0, NULL, 0, output, sizeof(output));
    ASSUME_ITS_EQUAL_I32(rc, 0);
}

FOSSIL_TEST(c_test_keygen_pbkdf2_sha256_known_answer) {
    // PBKDF2-HMAC-SHA256, password="password", salt="salt", iterations=1
    const uint8_t password[] = "password";
    const uint8_t salt[] = "salt";
    const uint8_t expected[32] = {
        0x12, 0x0f, 0xb6, 0xcf, 0xfc, 0xf8, 0xb3, 0x2c,
        0x43, 0xe7, 0x22, 0x52, 0x56, 0xc4, 0xf8, 0x37,
        0xa8, 0x65, 0x48, 0xc9, 0x2c, 0xcc, 0x35, 0x48,
        0x08, 0x05, 0x98, 0x7c, 0xb7, 0x0b, 0xe1, 0x7b
    };
    uint8_t output[sizeof(expected)];
    int rc = fossil_cryptic_keygen_pbkdf2_sha256(
        password, sizeof(password) - 1, salt, sizeof(salt) - 1, 1, output, sizeof(output));
    ASSUME_ITS_EQUAL_I32(rc, 0);
    ASSUME_ITS_TRUE(memcmp(output, expected, sizeof(expected)) == 0);
}

// * * * * * * * * * * * * * * * * * * * * * * * *
// * Fossil Logic Test Pool
// * * * * * * * * * * * * * * * * * * * * * * * *
FOSSIL_TEST_GROUP(c_keygen_tests) {
    FOSSIL_ADD_TEST(c_keygen_fixture, c_test_keygen_hkdf_sha256_rfc5869);
    FOSSIL_ADD_TEST(c_keygen_fixture, c_test_keygen_hkdf_sha256_optional_salt_info);
    FOSSIL_ADD_TEST(c_keygen_fixture, c_test_keygen_pbkdf2_sha256_known_answer);

    FOSSIL_ADD_SUITE(c_keygen_fixture);
} // end of tests
