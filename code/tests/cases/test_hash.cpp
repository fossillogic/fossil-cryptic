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

FOSSIL_TEST_SUITE(cpp_hash_fixture);

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

FOSSIL_TEST_CASE(cpp_test_crc32_oneshot) {
    const char *msg = "abc";
    char hex[9];
    int rc = fossil_cryptic_hash_compute("crc32", "u32", "hex", hex, sizeof(hex), msg, 3);
    ASSUME_ITS_EQUAL_I32(rc, 0);
    ASSUME_ITS_EQUAL_CSTR(hex, "352441c2");

    // C++ wrapper test
    std::string result = fossil::cryptic::Hash::compute("crc32", "u32", "hex", std::string(msg, 3));
    ASSUME_ITS_EQUAL_CSTR(result.c_str(), "352441c2");
}

FOSSIL_TEST_CASE(cpp_test_fnv1a32_oneshot) {
    const char *msg = "abc";
    char hex[9];
    int rc = fossil_cryptic_hash_compute("fnv32", "u32", "hex", hex, sizeof(hex), msg, 3);
    ASSUME_ITS_EQUAL_I32(rc, 0);
    ASSUME_ITS_EQUAL_CSTR(hex, "1a47e90b");

    std::string result = fossil::cryptic::Hash::compute("fnv32", "u32", "hex", std::string(msg, 3));
    ASSUME_ITS_EQUAL_CSTR(result.c_str(), "1a47e90b");
}

FOSSIL_TEST_CASE(cpp_test_fnv1a64_oneshot) {
    const char *msg = "abc";
    char hex[17];
    int rc = fossil_cryptic_hash_compute("fnv64", "u64", "hex", hex, sizeof(hex), msg, 3);
    ASSUME_ITS_EQUAL_I32(rc, 0);
    ASSUME_ITS_EQUAL_CSTR(hex, "e71fa2190541574b");

    std::string result = fossil::cryptic::Hash::compute("fnv64", "u64", "hex", std::string(msg, 3));
    ASSUME_ITS_EQUAL_CSTR(result.c_str(), "e71fa2190541574b");
}

FOSSIL_TEST_CASE(cpp_test_murmur3_oneshot) {
    const char *msg = "abc";
    char hex[9];
    int rc = fossil_cryptic_hash_compute("murmur3_32", "u32", "hex", hex, sizeof(hex), msg, 3);
    ASSUME_ITS_EQUAL_I32(rc, 0);
    ASSUME_ITS_EQUAL_CSTR(hex, "b3dd93fa");

    std::string result = fossil::cryptic::Hash::compute("murmur3_32", "u32", "hex", std::string(msg, 3));
    ASSUME_ITS_EQUAL_CSTR(result.c_str(), "b3dd93fa");
}

FOSSIL_TEST_CASE(cpp_test_crc64_oneshot) {
    const char *msg = "abc";
    char hex[17];
    int rc = fossil_cryptic_hash_compute("crc64", "u64", "hex", hex, sizeof(hex), msg, 3);
    ASSUME_ITS_EQUAL_I32(rc, 0);
    ASSUME_ITS_EQUAL_CSTR(hex, "2cd8094a1a277627");

    std::string result = fossil::cryptic::Hash::compute("crc64", "u64", "hex", std::string(msg, 3));
    ASSUME_ITS_EQUAL_CSTR(result.c_str(), "2cd8094a1a277627");
}

FOSSIL_TEST_CASE(cpp_test_djb2_oneshot) {
    const char *msg = "abc";
    char hex[9];
    int rc = fossil_cryptic_hash_compute("djb2", "u32", "hex", hex, sizeof(hex), msg, 3);
    ASSUME_ITS_EQUAL_I32(rc, 0);
    ASSUME_ITS_EQUAL_CSTR(hex, "0b885c8b");

    std::string result = fossil::cryptic::Hash::compute("djb2", "u32", "hex", std::string(msg, 3));
    ASSUME_ITS_EQUAL_CSTR(result.c_str(), "0b885c8b");
}

FOSSIL_TEST_CASE(cpp_test_sdbm_oneshot) {
    const char *msg = "abc";
    char hex[9];
    int rc = fossil_cryptic_hash_compute("sdbm", "u32", "hex", hex, sizeof(hex), msg, 3);
    ASSUME_ITS_EQUAL_I32(rc, 0);
    ASSUME_ITS_EQUAL_CSTR(hex, "3025f862");

    std::string result = fossil::cryptic::Hash::compute("sdbm", "u32", "hex", std::string(msg, 3));
    ASSUME_ITS_EQUAL_CSTR(result.c_str(), "3025f862");
}

FOSSIL_TEST_CASE(cpp_test_xor_oneshot) {
    const char *msg = "abc";
    char hex[9];
    int rc = fossil_cryptic_hash_compute("xor", "u32", "hex", hex, sizeof(hex), msg, 3);
    ASSUME_ITS_EQUAL_I32(rc, 0);
    ASSUME_ITS_EQUAL_CSTR(hex, "00000060");

    std::string result = fossil::cryptic::Hash::compute("xor", "u32", "hex", std::string(msg, 3));
    ASSUME_ITS_EQUAL_CSTR(result.c_str(), "00000060");
}

FOSSIL_TEST_CASE(cpp_test_cityhash32_oneshot) {
    const char *msg = "abc";
    char hex[9];
    int rc = fossil_cryptic_hash_compute("cityhash32", "u32", "hex", hex, sizeof(hex), msg, 3);
    ASSUME_ITS_EQUAL_I32(rc, 0);
    ASSUME_ITS_EQUAL_CSTR(hex, "00019bf5");

    std::string result = fossil::cryptic::Hash::compute("cityhash32", "u32", "hex", std::string(msg, 3));
    ASSUME_ITS_EQUAL_CSTR(result.c_str(), "00019bf5");
}

FOSSIL_TEST_CASE(cpp_test_cityhash64_oneshot) {
    const char *msg = "abc";
    char hex[17];
    int rc = fossil_cryptic_hash_compute("cityhash64", "u64", "hex", hex, sizeof(hex), msg, 3);
    ASSUME_ITS_EQUAL_I32(rc, 0);
    ASSUME_ITS_EQUAL_CSTR(hex, "00000000001939ae");

    std::string result = fossil::cryptic::Hash::compute("cityhash64", "u64", "hex", std::string(msg, 3));
    ASSUME_ITS_EQUAL_CSTR(result.c_str(), "00000000001939ae");
}

FOSSIL_TEST_CASE(cpp_test_xxhash32_oneshot) {
    const char *msg = "abc";
    char hex[9];
    int rc = fossil_cryptic_hash_compute("xxhash32", "u32", "hex", hex, sizeof(hex), msg, 3);
    ASSUME_ITS_EQUAL_I32(rc, 0);
    ASSUME_ITS_EQUAL_CSTR(hex, "159d90c6");

    std::string result = fossil::cryptic::Hash::compute("xxhash32", "u32", "hex", std::string(msg, 3));
    ASSUME_ITS_EQUAL_CSTR(result.c_str(), "159d90c6");
}

FOSSIL_TEST_CASE(cpp_test_xxhash64_oneshot) {
    const char *msg = "abc";
    char hex[17];
    int rc = fossil_cryptic_hash_compute("xxhash64", "u64", "hex", hex, sizeof(hex), msg, 3);
    ASSUME_ITS_EQUAL_I32(rc, 0);
    ASSUME_ITS_EQUAL_CSTR(hex, "530da1fae171f2df");

    std::string result = fossil::cryptic::Hash::compute("xxhash64", "u64", "hex", std::string(msg, 3));
    ASSUME_ITS_EQUAL_CSTR(result.c_str(), "530da1fae171f2df");
}

FOSSIL_TEST_CASE(cpp_test_murmur3_64_oneshot) {
    const char *msg = "abc";
    char hex[17];
    int rc = fossil_cryptic_hash_compute("murmur3_64", "u64", "hex", hex, sizeof(hex), msg, 3);
    ASSUME_ITS_EQUAL_I32(rc, 0);
    ASSUME_ITS_EQUAL_CSTR(hex, "b4963f3f3fad7867");

    std::string result = fossil::cryptic::Hash::compute("murmur3_64", "u64", "hex", std::string(msg, 3));
    ASSUME_ITS_EQUAL_CSTR(result.c_str(), "b4963f3f3fad7867");
}

FOSSIL_TEST_CASE(cpp_test_crc32_decpp_base) {
    const char *msg = "abc";
    char dec[12];
    int rc = fossil_cryptic_hash_compute("crc32", "u32", "dec", dec, sizeof(dec), msg, 3);
    ASSUME_ITS_EQUAL_I32(rc, 0);
    ASSUME_ITS_EQUAL_CSTR(dec, "891568578");

    std::string result = fossil::cryptic::Hash::compute("crc32", "u32", "dec", std::string(msg, 3));
    ASSUME_ITS_EQUAL_CSTR(result.c_str(), "891568578");
}

FOSSIL_TEST_CASE(cpp_test_crc32_oct_base) {
    const char *msg = "abc";
    char oct[12];
    int rc = fossil_cryptic_hash_compute("crc32", "u32", "oct", oct, sizeof(oct), msg, 3);
    ASSUME_ITS_EQUAL_I32(rc, 0);
    ASSUME_ITS_EQUAL_CSTR(oct, "6511040702");

    std::string result = fossil::cryptic::Hash::compute("crc32", "u32", "oct", std::string(msg, 3));
    ASSUME_ITS_EQUAL_CSTR(result.c_str(), "6511040702");
}

FOSSIL_TEST_CASE(cpp_test_crc32_bin_base) {
    const char *msg = "abc";
    char bin[33];
    int rc = fossil_cryptic_hash_compute("crc32", "u32", "bin", bin, sizeof(bin), msg, 3);
    ASSUME_ITS_EQUAL_I32(rc, 0);
    ASSUME_ITS_EQUAL_CSTR(bin, "00110101001001000100000111000010");

    std::string result = fossil::cryptic::Hash::compute("crc32", "u32", "bin", std::string(msg, 3));
    ASSUME_ITS_EQUAL_CSTR(result.c_str(), "00110101001001000100000111000010");
}

FOSSIL_TEST_CASE(cpp_test_invalid_algorithm) {
    const char *msg = "abc";
    char hex[9];
    int rc = fossil_cryptic_hash_compute("notahash", "u32", "hex", hex, sizeof(hex), msg, 3);
    ASSUME_ITS_EQUAL_I32(rc, -3);

    try {
        (void)fossil::cryptic::Hash::compute("notahash", "u32", "hex", std::string(msg, 3));
        ASSUME_ITS_FALSE("Expected exception for invalid algorithm");
    } catch (const std::runtime_error&) {
        // Expected
    }
}

FOSSIL_TEST_CASE(cpp_test_invalid_bits) {
    const char *msg = "abc";
    char hex[9];
    int rc = fossil_cryptic_hash_compute("crc32", "u128", "hex", hex, sizeof(hex), msg, 3);
    ASSUME_ITS_EQUAL_I32(rc, -2);

    try {
        (void)fossil::cryptic::Hash::compute("crc32", "u128", "hex", std::string(msg, 3));
        ASSUME_ITS_FALSE("Expected exception for invalid bits");
    } catch (const std::runtime_error&) {
        // Expected
    }
}

FOSSIL_TEST_CASE(cpp_test_invalid_base) {
    const char *msg = "abc";
    char buf[32];
    int rc = fossil_cryptic_hash_compute("crc32", "u32", "base99", buf, sizeof(buf), msg, 3);
    ASSUME_ITS_EQUAL_I32(rc, -4);

    try {
        (void)fossil::cryptic::Hash::compute("crc32", "u32", "base99", std::string(msg, 3));
        ASSUME_ITS_FALSE("Expected exception for invalid base");
    } catch (const std::runtime_error&) {
        // Expected
    }
}

FOSSIL_TEST_CASE(cpp_test_null_args) {
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

    // C++ wrapper: should throw std::invalid_argument if input is empty or null
    try {
        (void)fossil::cryptic::Hash::compute("", "u32", "hex", std::string("abc", 3));
        ASSUME_ITS_FALSE("Expected exception for empty algorithm");
    } catch (const std::runtime_error&) {
        // Acceptable, as wrapper throws runtime_error on error
    }
}

// * * * * * * * * * * * * * * * * * * * * * * * *
// * Fossil Logic Test Pool
// * * * * * * * * * * * * * * * * * * * * * * * *
FOSSIL_TEST_GROUP(cpp_hash_tests) {
    FOSSIL_TEST_ADD(cpp_hash_fixture, cpp_test_crc32_oneshot);
    FOSSIL_TEST_ADD(cpp_hash_fixture, cpp_test_fnv1a32_oneshot);
    FOSSIL_TEST_ADD(cpp_hash_fixture, cpp_test_fnv1a64_oneshot);
    FOSSIL_TEST_ADD(cpp_hash_fixture, cpp_test_murmur3_oneshot);
    FOSSIL_TEST_ADD(cpp_hash_fixture, cpp_test_crc64_oneshot);
    FOSSIL_TEST_ADD(cpp_hash_fixture, cpp_test_djb2_oneshot);
    FOSSIL_TEST_ADD(cpp_hash_fixture, cpp_test_sdbm_oneshot);
    FOSSIL_TEST_ADD(cpp_hash_fixture, cpp_test_xor_oneshot);
    FOSSIL_TEST_ADD(cpp_hash_fixture, cpp_test_cityhash32_oneshot);
    FOSSIL_TEST_ADD(cpp_hash_fixture, cpp_test_cityhash64_oneshot);
    FOSSIL_TEST_ADD(cpp_hash_fixture, cpp_test_xxhash32_oneshot);
    FOSSIL_TEST_ADD(cpp_hash_fixture, cpp_test_xxhash64_oneshot);
    FOSSIL_TEST_ADD(cpp_hash_fixture, cpp_test_murmur3_64_oneshot);
    FOSSIL_TEST_ADD(cpp_hash_fixture, cpp_test_crc32_decpp_base);
    FOSSIL_TEST_ADD(cpp_hash_fixture, cpp_test_crc32_oct_base);
    FOSSIL_TEST_ADD(cpp_hash_fixture, cpp_test_crc32_bin_base);
    FOSSIL_TEST_ADD(cpp_hash_fixture, cpp_test_invalid_algorithm);
    FOSSIL_TEST_ADD(cpp_hash_fixture, cpp_test_invalid_bits);
    FOSSIL_TEST_ADD(cpp_hash_fixture, cpp_test_invalid_base);
    FOSSIL_TEST_ADD(cpp_hash_fixture, cpp_test_null_args);

    FOSSIL_TEST_REGISTER(cpp_hash_fixture);
} // end of tests
