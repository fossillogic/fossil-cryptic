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

FOSSIL_SUITE(cpp_hash_fixture);

FOSSIL_SETUP(cpp_hash_fixture) {
    // Setup the test fixture
}

FOSSIL_TEARDOWN(cpp_hash_fixture) {
    // Teardown the test fixture
}

// * * * * * * * * * * * * * * * * * * * * * * * *
// * Fossil Logic Test Cases
// * * * * * * * * * * * * * * * * * * * * * * * *
// The test cases below are provided as samples, inspired
// by the Meson build system's approach of using test cases
// as samples for library usage.
// * * * * * * * * * * * * * * * * * * * * * * * *

FOSSIL_TEST(cpp_test_crc32_oneshot) {
    const char *msg = "abc";
    ASSUME_ITS_EQUAL_I32(fossil::cryptic::Hash::crc32(msg, 3), 0x352441c2u);
}

FOSSIL_TEST(cpp_test_fnv1a32_oneshot) {
    const char *msg = "abc";
    ASSUME_ITS_EQUAL_I32(fossil::cryptic::Hash::fnv32(msg, 3), 0x1a47e90bu);
}

FOSSIL_TEST(cpp_test_fnv1a64_oneshot) {
    const char *msg = "abc";
    ASSUME_ITS_EQUAL_I64(fossil::cryptic::Hash::fnv64(msg, 3), 0xe71fa2190541574bULL);
}

FOSSIL_TEST(cpp_test_crc64_oneshot) {
    const char *msg = "abc";
    ASSUME_ITS_EQUAL_I64(fossil::cryptic::Hash::crc64(msg, 3), 0x2cd8094a1a277627ULL);
}

FOSSIL_TEST(cpp_test_djb2_oneshot) {
    const char *msg = "abc";
    ASSUME_ITS_EQUAL_I32(fossil::cryptic::Hash::djb2(msg, 3), 0x0b885c8bu);
}

FOSSIL_TEST(cpp_test_sdbm_oneshot) {
    const char *msg = "abc";
    ASSUME_ITS_EQUAL_I32(fossil::cryptic::Hash::sdbm(msg, 3), 0x3025f862u);
}

FOSSIL_TEST(cpp_test_hash_blake2b_512_binary) {
    const char *msg = "abc";
    const uint8_t expected[64] = {
        0xba, 0x80, 0xa5, 0x3f, 0x98, 0x1c, 0x4d, 0x0d,
        0x6a, 0x27, 0x97, 0xb6, 0x9f, 0x12, 0xf6, 0xe9,
        0x4c, 0x21, 0x2f, 0x14, 0x68, 0x5a, 0xc4, 0xb7,
        0x4b, 0x12, 0xbb, 0x6f, 0xdb, 0xff, 0xa2, 0xd1,
        0x7d, 0x87, 0xc5, 0x39, 0x2a, 0xab, 0x79, 0x2d,
        0xc2, 0x52, 0xd5, 0xde, 0x45, 0x33, 0xcc, 0x95,
        0x18, 0xd3, 0x8a, 0xa8, 0xdb, 0xf1, 0x92, 0x5a,
        0xb9, 0x23, 0x86, 0xed, 0xd4, 0x00, 0x99, 0x23
    };
    const auto out = fossil::cryptic::Hash::blake2b_512(msg, 3);
    for (size_t i = 0; i < out.size(); ++i) {
        ASSUME_ITS_EQUAL_I32(out[i], expected[i]);
    }
}

FOSSIL_TEST(cpp_test_hash_blake2b_256_binary) {
    const char *msg = "abc";
    const uint8_t expected[32] = {
        0xbd, 0xdd, 0x81, 0x3c, 0x63, 0x42, 0x39, 0x72,
        0x31, 0x71, 0xef, 0x3f, 0xee, 0x98, 0x57, 0x9b,
        0x94, 0x96, 0x4e, 0x3b, 0xb1, 0xcb, 0x3e, 0x42,
        0x72, 0x62, 0xc8, 0xc0, 0x68, 0xd5, 0x23, 0x19
    };
    const auto out = fossil::cryptic::Hash::blake2b_256(msg, 3);
    for (size_t i = 0; i < out.size(); ++i) {
        ASSUME_ITS_EQUAL_I32(out[i], expected[i]);
    }
}

FOSSIL_TEST(cpp_test_hash_sha256_binary) {
    const char *msg = "abc";
    const uint8_t expected[32] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
    };
    const auto out = fossil::cryptic::Hash::sha256(msg, 3);
    for (size_t i = 0; i < out.size(); ++i) {
        ASSUME_ITS_EQUAL_I32(out[i], expected[i]);
    }
}

FOSSIL_TEST(cpp_test_hash_sha512_binary) {
    const char *msg = "abc";
    const uint8_t expected[64] = {
        0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba,
        0xcc, 0x41, 0x73, 0x49, 0xae, 0x20, 0x41, 0x31,
        0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2,
        0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a,
        0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8,
        0x36, 0xba, 0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd,
        0x45, 0xd4, 0x42, 0x36, 0x43, 0xce, 0x80, 0xe2,
        0xa9, 0xac, 0x94, 0xfa, 0x54, 0xca, 0x49, 0xf
    };
    const auto out = fossil::cryptic::Hash::sha512(msg, 3);
    for (size_t i = 0; i < out.size(); ++i) {
        ASSUME_ITS_EQUAL_I32(out[i], expected[i]);
    }
}

FOSSIL_TEST(cpp_test_hash_utility_functions) {
    const char *msg = "abc";
    ASSUME_ITS_EQUAL_I32(fossil::cryptic::Hash::crc32(msg, 3), 0x352441c2u);
    ASSUME_ITS_EQUAL_I64(fossil::cryptic::Hash::crc64(msg, 3), 0x2cd8094a1a277627ULL);
    ASSUME_ITS_EQUAL_I32(fossil::cryptic::Hash::fnv32(msg, 3), 0x1a47e90bu);
    ASSUME_ITS_EQUAL_I64(fossil::cryptic::Hash::fnv64(msg, 3), 0xe71fa2190541574bULL);
    ASSUME_ITS_EQUAL_I32(fossil::cryptic::Hash::djb2(msg, 3), 0x0b885c8bu);
    ASSUME_ITS_EQUAL_I32(fossil::cryptic::Hash::sdbm(msg, 3), 0x3025f862u);
}

// * * * * * * * * * * * * * * * * * * * * * * * *
// * Fossil Logic Test Pool
// * * * * * * * * * * * * * * * * * * * * * * * *
FOSSIL_TEST_GROUP(cpp_hash_tests) {
    FOSSIL_ADD_TEST(cpp_hash_fixture, cpp_test_crc32_oneshot);
    FOSSIL_ADD_TEST(cpp_hash_fixture, cpp_test_fnv1a32_oneshot);
    FOSSIL_ADD_TEST(cpp_hash_fixture, cpp_test_fnv1a64_oneshot);
    FOSSIL_ADD_TEST(cpp_hash_fixture, cpp_test_crc64_oneshot);
    FOSSIL_ADD_TEST(cpp_hash_fixture, cpp_test_djb2_oneshot);
    FOSSIL_ADD_TEST(cpp_hash_fixture, cpp_test_sdbm_oneshot);
    FOSSIL_ADD_TEST(cpp_hash_fixture, cpp_test_hash_blake2b_512_binary);
    FOSSIL_ADD_TEST(cpp_hash_fixture, cpp_test_hash_blake2b_256_binary);
    FOSSIL_ADD_TEST(cpp_hash_fixture, cpp_test_hash_sha256_binary);
    FOSSIL_ADD_TEST(cpp_hash_fixture, cpp_test_hash_sha512_binary);
    FOSSIL_ADD_TEST(cpp_hash_fixture, cpp_test_hash_utility_functions);

    FOSSIL_ADD_SUITE(cpp_hash_fixture);
} // end of tests
