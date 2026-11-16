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

FOSSIL_TEST(c_test_crc32_oneshot) {
    const char *msg = "abc";
    char hex[9];
    int rc = fossil_cryptic_hash_compute("crc32", "u32", "hex", hex, sizeof(hex), msg, 3);
    ASSUME_ITS_EQUAL_I32(rc, 0);
    ASSUME_ITS_EQUAL_CSTR(hex, "352441c2");
}

FOSSIL_TEST(c_test_fnv1a32_oneshot) {
    const char *msg = "abc";
    char hex[9];
    int rc = fossil_cryptic_hash_compute("fnv32", "u32", "hex", hex, sizeof(hex), msg, 3);
    ASSUME_ITS_EQUAL_I32(rc, 0);
    // The expected value may differ depending on fnv32 implementation
    // Update as needed to match your fnv32 output for "abc"
    ASSUME_ITS_EQUAL_CSTR(hex, "1a47e90b");
}

FOSSIL_TEST(c_test_fnv1a64_oneshot) {
    const char *msg = "abc";
    char hex[17];
    int rc = fossil_cryptic_hash_compute("fnv64", "u64", "hex", hex, sizeof(hex), msg, 3);
    ASSUME_ITS_EQUAL_I32(rc, 0);
    // The expected value may differ depending on fnv64 implementation
    // Update as needed to match your fnv64 output for "abc"
    ASSUME_ITS_EQUAL_CSTR(hex, "e71fa2190541574b");
}

FOSSIL_TEST(c_test_murmur3_oneshot) {
    const char *msg = "abc";
    char hex[9];
    int rc = fossil_cryptic_hash_compute("murmur3_32", "u32", "hex", hex, sizeof(hex), msg, 3);
    ASSUME_ITS_EQUAL_I32(rc, 0);
    ASSUME_ITS_EQUAL_CSTR(hex, "b3dd93fa");
}

FOSSIL_TEST(c_test_crc64_oneshot) {
    const char *msg = "abc";
    char hex[17];
    int rc = fossil_cryptic_hash_compute("crc64", "u64", "hex", hex, sizeof(hex), msg, 3);
    ASSUME_ITS_EQUAL_I32(rc, 0);
    // The expected value may differ depending on crc64 implementation
    ASSUME_ITS_EQUAL_CSTR(hex, "2cd8094a1a277627"); // Update if needed
}

FOSSIL_TEST(c_test_djb2_oneshot) {
    const char *msg = "abc";
    char hex[9];
    int rc = fossil_cryptic_hash_compute("djb2", "u32", "hex", hex, sizeof(hex), msg, 3);
    ASSUME_ITS_EQUAL_I32(rc, 0);
    ASSUME_ITS_EQUAL_CSTR(hex, "0b885c8b");
}

FOSSIL_TEST(c_test_sdbm_oneshot) {
    const char *msg = "abc";
    char hex[9];
    int rc = fossil_cryptic_hash_compute("sdbm", "u32", "hex", hex, sizeof(hex), msg, 3);
    ASSUME_ITS_EQUAL_I32(rc, 0);
    ASSUME_ITS_EQUAL_CSTR(hex, "3025f862");
}

FOSSIL_TEST(c_test_xor_oneshot) {
    const char *msg = "abc";
    char hex[9];
    int rc = fossil_cryptic_hash_compute("xor", "u32", "hex", hex, sizeof(hex), msg, 3);
    ASSUME_ITS_EQUAL_I32(rc, 0);
    ASSUME_ITS_EQUAL_CSTR(hex, "00000060");
}

FOSSIL_TEST(c_test_cityhash32_oneshot) {
    const char *msg = "abc";
    char hex[9];
    int rc = fossil_cryptic_hash_compute("cityhash32", "u32", "hex", hex, sizeof(hex), msg, 3);
    ASSUME_ITS_EQUAL_I32(rc, 0);
    ASSUME_ITS_EQUAL_CSTR(hex, "00019bf5");
}

FOSSIL_TEST(c_test_cityhash64_oneshot) {
    const char *msg = "abc";
    char hex[17];
    int rc = fossil_cryptic_hash_compute("cityhash64", "u64", "hex", hex, sizeof(hex), msg, 3);
    ASSUME_ITS_EQUAL_I32(rc, 0);
    ASSUME_ITS_EQUAL_CSTR(hex, "00000000001939ae");
}

FOSSIL_TEST(c_test_xxhash32_oneshot) {
    const char *msg = "abc";
    char hex[9];
    int rc = fossil_cryptic_hash_compute("xxhash32", "u32", "hex", hex, sizeof(hex), msg, 3);
    ASSUME_ITS_EQUAL_I32(rc, 0);
    ASSUME_ITS_EQUAL_CSTR(hex, "159d90c6");
}

FOSSIL_TEST(c_test_xxhash64_oneshot) {
    const char *msg = "abc";
    char hex[17];
    int rc = fossil_cryptic_hash_compute("xxhash64", "u64", "hex", hex, sizeof(hex), msg, 3);
    ASSUME_ITS_EQUAL_I32(rc, 0);
    ASSUME_ITS_EQUAL_CSTR(hex, "530da1fae171f2df");
}

FOSSIL_TEST(c_test_murmur3_64_oneshot) {
    const char *msg = "abc";
    char hex[17];
    int rc = fossil_cryptic_hash_compute("murmur3_64", "u64", "hex", hex, sizeof(hex), msg, 3);
    ASSUME_ITS_EQUAL_I32(rc, 0);
    // The expected value may differ depending on implementation
    ASSUME_ITS_EQUAL_CSTR(hex, "b4963f3f3fad7867"); // Update if needed
}

FOSSIL_TEST(c_test_crc32_dec_base) {
    const char *msg = "abc";
    char dec[12];
    int rc = fossil_cryptic_hash_compute("crc32", "u32", "dec", dec, sizeof(dec), msg, 3);
    ASSUME_ITS_EQUAL_I32(rc, 0);
    ASSUME_ITS_EQUAL_CSTR(dec, "891568578");
}

FOSSIL_TEST(c_test_crc32_oct_base) {
    const char *msg = "abc";
    char oct[12];
    int rc = fossil_cryptic_hash_compute("crc32", "u32", "oct", oct, sizeof(oct), msg, 3);
    ASSUME_ITS_EQUAL_I32(rc, 0);
    ASSUME_ITS_EQUAL_CSTR(oct, "6511040702");
}

FOSSIL_TEST(c_test_crc32_bin_base) {
    const char *msg = "abc";
    char bin[33];
    int rc = fossil_cryptic_hash_compute("crc32", "u32", "bin", bin, sizeof(bin), msg, 3);
    ASSUME_ITS_EQUAL_I32(rc, 0);
    ASSUME_ITS_EQUAL_CSTR(bin, "00110101001001000100000111000010");
}

FOSSIL_TEST(c_test_hash_blake2b_512_binary) {
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
    uint8_t out[64];
    int rc = fossil_cryptic_hash_blake2b_512(msg, 3, out);
    ASSUME_ITS_EQUAL_I32(rc, 0);
    for (size_t i = 0; i < sizeof(out); ++i) {
        ASSUME_ITS_EQUAL_I32(out[i], expected[i]);
    }
}

FOSSIL_TEST(c_test_hash_blake2b_256_binary) {
    const char *msg = "abc";
    const uint8_t expected[32] = {
        0xbd, 0xdd, 0x81, 0x3c, 0x63, 0x42, 0x39, 0x72,
        0x31, 0x71, 0xef, 0x3f, 0xee, 0x98, 0x57, 0x9b,
        0x94, 0x96, 0x4e, 0x3b, 0xb1, 0xcb, 0x3e, 0x42,
        0x72, 0x62, 0xc8, 0xc0, 0x68, 0xd5, 0x23, 0x19
    };
    uint8_t out[32];
    int rc = fossil_cryptic_hash_blake2b_256(msg, 3, out);
    ASSUME_ITS_EQUAL_I32(rc, 0);
    for (size_t i = 0; i < sizeof(out); ++i) {
        ASSUME_ITS_EQUAL_I32(out[i], expected[i]);
    }
}

FOSSIL_TEST(c_test_hash_sha256_binary) {
    const char *msg = "abc";
    const uint8_t expected[32] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
    };
    uint8_t out[32];
    int rc = fossil_cryptic_hash_sha256(msg, 3, out);
    ASSUME_ITS_EQUAL_I32(rc, 0);
    for (size_t i = 0; i < sizeof(out); ++i) {
        ASSUME_ITS_EQUAL_I32(out[i], expected[i]);
    }
}

FOSSIL_TEST(c_test_hash_sha512_binary) {
    const char *msg = "abc";
    const uint8_t expected[64] = {
        0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba,
        0xcc, 0x41, 0x73, 0x49, 0xae, 0x20, 0x41, 0x31,
        0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2,
        0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a,
        0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8,
        0x36, 0xba, 0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd,
        0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e,
        0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f
    };
    uint8_t out[64];
    int rc = fossil_cryptic_hash_sha512(msg, 3, out);
    ASSUME_ITS_EQUAL_I32(rc, 0);
    for (size_t i = 0; i < sizeof(out); ++i) {
        ASSUME_ITS_EQUAL_I32(out[i], expected[i]);
    }
}

FOSSIL_TEST(c_test_hash_utility_functions) {
    const char *msg = "abc";
    ASSUME_ITS_EQUAL_I32(fossil_cryptic_hash_crc32(msg, 3), 0x352441c2u);
    ASSUME_ITS_EQUAL_I64(fossil_cryptic_hash_crc64(msg, 3), 0x2cd8094a1a277627ULL);
    ASSUME_ITS_EQUAL_I32(fossil_cryptic_hash_fnv32(msg, 3), 0x1a47e90bu);
    ASSUME_ITS_EQUAL_I64(fossil_cryptic_hash_fnv64(msg, 3), 0xe71fa2190541574bULL);
    ASSUME_ITS_EQUAL_I32(fossil_cryptic_hash_djb2(msg, 3), 0x0b885c8bu);
    ASSUME_ITS_EQUAL_I32(fossil_cryptic_hash_sdbm(msg, 3), 0x3025f862u);
}

FOSSIL_TEST(c_test_invalid_algorithm) {
    const char *msg = "abc";
    char hex[9];
    int rc = fossil_cryptic_hash_compute("notahash", "u32", "hex", hex, sizeof(hex), msg, 3);
    ASSUME_ITS_EQUAL_I32(rc, -3);
}

FOSSIL_TEST(c_test_invalid_bits) {
    const char *msg = "abc";
    char hex[9];
    int rc = fossil_cryptic_hash_compute("crc32", "u128", "hex", hex, sizeof(hex), msg, 3);
    ASSUME_ITS_EQUAL_I32(rc, -2);
}

FOSSIL_TEST(c_test_invalid_base) {
    const char *msg = "abc";
    char buf[32];
    int rc = fossil_cryptic_hash_compute("crc32", "u32", "base99", buf, sizeof(buf), msg, 3);
    ASSUME_ITS_EQUAL_I32(rc, -4);
}

FOSSIL_TEST(c_test_null_args) {
    char hex[9];
    int rc = fossil_cryptic_hash_compute(NULL, "u32", "hex", hex, sizeof(hex), "abc", 3);
    ASSUME_ITS_EQUAL_I32(rc, -1);
    rc = fossil_cryptic_hash_compute("crc32", NULL, "hex", hex, sizeof(hex), "abc", 3);
    ASSUME_ITS_EQUAL_I32(rc, -1);
    rc = fossil_cryptic_hash_compute("crc32", "u32", NULL, hex, sizeof(hex), "abc", 3);
    ASSUME_ITS_EQUAL_I32(rc, -1);
    rc = fossil_cryptic_hash_compute("crc32", "u32", "hex", NULL, sizeof(hex), "abc", 3);
    ASSUME_ITS_EQUAL_I32(rc, -1);
    rc = fossil_cryptic_hash_compute("crc32", "u32", "hex", hex, sizeof(hex), NULL, 3);
    ASSUME_ITS_EQUAL_I32(rc, -1);
}

// * * * * * * * * * * * * * * * * * * * * * * * *
// * Fossil Logic Test Pool
// * * * * * * * * * * * * * * * * * * * * * * * *
FOSSIL_TEST_GROUP(c_hash_tests) {
    FOSSIL_ADD_TEST(c_hash_fixture, c_test_crc32_oneshot);
    FOSSIL_ADD_TEST(c_hash_fixture, c_test_fnv1a32_oneshot);
    FOSSIL_ADD_TEST(c_hash_fixture, c_test_fnv1a64_oneshot);
    FOSSIL_ADD_TEST(c_hash_fixture, c_test_murmur3_oneshot);
    FOSSIL_ADD_TEST(c_hash_fixture, c_test_crc64_oneshot);
    FOSSIL_ADD_TEST(c_hash_fixture, c_test_djb2_oneshot);
    FOSSIL_ADD_TEST(c_hash_fixture, c_test_sdbm_oneshot);
    FOSSIL_ADD_TEST(c_hash_fixture, c_test_xor_oneshot);
    FOSSIL_ADD_TEST(c_hash_fixture, c_test_cityhash32_oneshot);
    FOSSIL_ADD_TEST(c_hash_fixture, c_test_cityhash64_oneshot);
    FOSSIL_ADD_TEST(c_hash_fixture, c_test_xxhash32_oneshot);
    FOSSIL_ADD_TEST(c_hash_fixture, c_test_xxhash64_oneshot);
    FOSSIL_ADD_TEST(c_hash_fixture, c_test_murmur3_64_oneshot);
    FOSSIL_ADD_TEST(c_hash_fixture, c_test_crc32_dec_base);
    FOSSIL_ADD_TEST(c_hash_fixture, c_test_crc32_oct_base);
    FOSSIL_ADD_TEST(c_hash_fixture, c_test_crc32_bin_base);
    FOSSIL_ADD_TEST(c_hash_fixture, c_test_hash_blake2b_512_binary);
    FOSSIL_ADD_TEST(c_hash_fixture, c_test_hash_blake2b_256_binary);
    FOSSIL_ADD_TEST(c_hash_fixture, c_test_hash_sha256_binary);
    FOSSIL_ADD_TEST(c_hash_fixture, c_test_hash_sha512_binary);
    FOSSIL_ADD_TEST(c_hash_fixture, c_test_hash_utility_functions);
    FOSSIL_ADD_TEST(c_hash_fixture, c_test_invalid_algorithm);
    FOSSIL_ADD_TEST(c_hash_fixture, c_test_invalid_bits);
    FOSSIL_ADD_TEST(c_hash_fixture, c_test_invalid_base);
    FOSSIL_ADD_TEST(c_hash_fixture, c_test_null_args);

    FOSSIL_ADD_SUITE(c_hash_fixture);
} // end of tests
