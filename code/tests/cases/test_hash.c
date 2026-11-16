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

FOSSIL_SUITE(c_hash_fixture);

FOSSIL_SETUP(c_hash_fixture) {
    // Setup the test fixture
}

FOSSIL_TEARDOWN(c_hash_fixture) {
    // Teardown the test fixture
}

// * * * * * * * * * * * * * * * * * * * * * * * *
// * Fossil Logic Test Cases
// * * * * * * * * * * * * * * * * * * * * * * * *
// The test cases below are provided as samples, inspired
// by the Meson build system's approach of using test cases
// as samples for library usage.
// * * * * * * * * * * * * * * * * * * * * * * * *

FOSSIL_TEST(c_test_hash_blake2b_512) {
    static const uint8_t expected[64] = {
        0xba, 0x80, 0xa5, 0x3f, 0x98, 0x1c, 0x4d, 0x0d,
        0x6a, 0x27, 0x9b, 0x69, 0xf1, 0x2f, 0x6e, 0x94,
        0xc2, 0x12, 0xf1, 0x46, 0x85, 0xac, 0x4b, 0x74,
        0xb1, 0x2b, 0xb6, 0xfd, 0xbf, 0xfa, 0x2d, 0x0d,
        0xd8, 0x7c, 0x53, 0x92, 0xaa, 0xb7, 0x92, 0xdc,
        0x25, 0x2d, 0x5d, 0xe4, 0x53, 0x3c, 0xc9, 0x51,
        0x8d, 0x38, 0xaa, 0x8d, 0xbf, 0x19, 0x25, 0xab,
        0x92, 0x38, 0x6e, 0xdd, 0x40, 0x09, 0x92, 0x3f
    };
    uint8_t digest[64];

    ASSUME_ITS_EQUAL_I32(fossil_cryptic_hash_blake2b_512("abc", 3, digest), 0);
    ASSUME_ITS_TRUE(memcmp(digest, expected, sizeof(expected)) == 0);
}

FOSSIL_TEST(c_test_hash_blake2b_256) {
    static const uint8_t expected[32] = {
        0xbd, 0xdd, 0x81, 0x3c, 0x63, 0x42, 0x39, 0x72,
        0x31, 0x7e, 0xf3, 0xfe, 0xe9, 0x85, 0x79, 0xb9,
        0x49, 0x64, 0xe3, 0xbb, 0x1c, 0xb3, 0xe4, 0x27,
        0x26, 0x2c, 0x8c, 0x06, 0x8d, 0x52, 0x31, 0x09
    };
    uint8_t digest[32];

    ASSUME_ITS_EQUAL_I32(fossil_cryptic_hash_blake2b_256("abc", 3, digest), 0);
    ASSUME_ITS_TRUE(memcmp(digest, expected, sizeof(expected)) == 0);
}

FOSSIL_TEST(c_test_hash_sha256) {
    static const uint8_t expected[32] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
    };
    uint8_t digest[32];

    ASSUME_ITS_EQUAL_I32(fossil_cryptic_hash_sha256("abc", 3, digest), 0);
    ASSUME_ITS_TRUE(memcmp(digest, expected, sizeof(expected)) == 0);
}

FOSSIL_TEST(c_test_hash_sha512) {
    static const uint8_t expected[64] = {
        0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba,
        0xcc, 0x41, 0x73, 0x49, 0xae, 0x20, 0x41, 0x31,
        0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2,
        0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a,
        0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8,
        0x36, 0xba, 0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd,
        0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e,
        0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f
    };
    uint8_t digest[64];

    ASSUME_ITS_EQUAL_I32(fossil_cryptic_hash_sha512("abc", 3, digest), 0);
    ASSUME_ITS_TRUE(memcmp(digest, expected, sizeof(expected)) == 0);
}

FOSSIL_TEST(c_test_hash_utility_functions) {
    const char input[] = "abc";
    const char other[] = "abd";

    ASSUME_ITS_TRUE(fossil_cryptic_hash_crc32(input, 3) == fossil_cryptic_hash_crc32(input, 3));
    ASSUME_ITS_TRUE(fossil_cryptic_hash_crc32(input, 3) != fossil_cryptic_hash_crc32(other, 3));
    ASSUME_ITS_TRUE(fossil_cryptic_hash_crc64(input, 3) == fossil_cryptic_hash_crc64(input, 3));
    ASSUME_ITS_TRUE(fossil_cryptic_hash_crc64(input, 3) != fossil_cryptic_hash_crc64(other, 3));
    ASSUME_ITS_TRUE(fossil_cryptic_hash_fnv32(input, 3) == fossil_cryptic_hash_fnv32(input, 3));
    ASSUME_ITS_TRUE(fossil_cryptic_hash_fnv32(input, 3) != fossil_cryptic_hash_fnv32(other, 3));
    ASSUME_ITS_TRUE(fossil_cryptic_hash_fnv64(input, 3) == fossil_cryptic_hash_fnv64(input, 3));
    ASSUME_ITS_TRUE(fossil_cryptic_hash_fnv64(input, 3) != fossil_cryptic_hash_fnv64(other, 3));
    ASSUME_ITS_TRUE(fossil_cryptic_hash_djb2(input, 3) == fossil_cryptic_hash_djb2(input, 3));
    ASSUME_ITS_TRUE(fossil_cryptic_hash_djb2(input, 3) != fossil_cryptic_hash_djb2(other, 3));
    ASSUME_ITS_TRUE(fossil_cryptic_hash_sdbm(input, 3) == fossil_cryptic_hash_sdbm(input, 3));
    ASSUME_ITS_TRUE(fossil_cryptic_hash_sdbm(input, 3) != fossil_cryptic_hash_sdbm(other, 3));
}

// * * * * * * * * * * * * * * * * * * * * * * * *
// * Fossil Logic Test Pool
// * * * * * * * * * * * * * * * * * * * * * * * *
FOSSIL_TEST_GROUP(c_hash_tests) {
    FOSSIL_ADD_TEST(c_hash_fixture, c_test_hash_blake2b_512);
    FOSSIL_ADD_TEST(c_hash_fixture, c_test_hash_blake2b_256);
    FOSSIL_ADD_TEST(c_hash_fixture, c_test_hash_sha256);
    FOSSIL_ADD_TEST(c_hash_fixture, c_test_hash_sha512);
    FOSSIL_ADD_TEST(c_hash_fixture, c_test_hash_utility_functions);

    FOSSIL_ADD_SUITE(c_hash_fixture);
} // end of hash tests
