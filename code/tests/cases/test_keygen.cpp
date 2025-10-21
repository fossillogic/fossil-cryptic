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

FOSSIL_TEST_SUITE(cpp_keygen_fixture);

FOSSIL_SETUP(cpp_keygen_fixture) {
    // Setup the test fixture
}

FOSSIL_TEARDOWN(cpp_keygen_fixture) {
    // Teardown the test fixture
}

// * * * * * * * * * * * * * * * * * * * * * * * *
// * Fossil Logic Test Cases
// * * * * * * * * * * * * * * * * * * * * * * * *
// The test cases below are provided as samples, inspired
// by the Meson build system's approach of using test cases
// as samples for library usage.
// * * * * * * * * * * * * * * * * * * * * * * * *

FOSSIL_TEST_CASE(cpp_test_keygen_compute_basicpp_fnv_hex_u32) {
    // Basic FNV keygen, hex, u32
    std::string key = fossil::cryptic::Keygen::compute("fnv", "u32", "hex", "hello");
    ASSUME_ITS_TRUE(key.length() == 8); // 8 hex digits for u32
}

FOSSIL_TEST_CASE(cpp_test_keygen_compute_basicpp_fnv_hex_u64) {
    // Basic FNV keygen, hex, u64
    std::string key = fossil::cryptic::Keygen::compute("fnv", "u64", "hex", "hello");
    ASSUME_ITS_TRUE(key.length() == 16); // 16 hex digits for u64
}

FOSSIL_TEST_CASE(cpp_test_keygen_compute_crcpp_base64_u32) {
    // CRC keygen, base64, u32
    std::string key = fossil::cryptic::Keygen::compute("crc", "u32", "base64", "seed");
    ASSUME_ITS_TRUE(key.length() > 0);
}

FOSSIL_TEST_CASE(cpp_test_keygen_compute_mix_auto_auto) {
    // Mix algorithm, auto bits, auto base
    std::string key = fossil::cryptic::Keygen::compute("mix", "auto", "auto", "longseedvalue");
    ASSUME_ITS_TRUE(key.length() > 0);
}

FOSSIL_TEST_CASE(cpp_test_keygen_compute_null_arguments) {
    // Should throw with null arguments
    try {
        fossil::cryptic::Keygen::compute("", "u32", "hex", "seed");
        ASSUME_ITS_TRUE(false); // Should not reach here
    } catch (...) {
        ASSUME_ITS_TRUE(true);
    }
    try {
        fossil::cryptic::Keygen::compute("fnv", "", "hex", "seed");
        ASSUME_ITS_TRUE(false);
    } catch (...) {
        ASSUME_ITS_TRUE(true);
    }
    try {
        fossil::cryptic::Keygen::compute("fnv", "u32", "", "seed");
        ASSUME_ITS_TRUE(false);
    } catch (...) {
        ASSUME_ITS_TRUE(true);
    }
    try {
        fossil::cryptic::Keygen::compute("fnv", "u32", "hex", "");
        ASSUME_ITS_TRUE(false);
    } catch (...) {
        ASSUME_ITS_TRUE(true);
    }
}

FOSSIL_TEST_CASE(cpp_test_keygen_compute_unsupported_algorithm) {
    // Unsupported algorithm should throw
    try {
        fossil::cryptic::Keygen::compute("unknown", "u32", "hex", "seed");
        ASSUME_ITS_TRUE(false);
    } catch (const std::runtime_error&) {
        ASSUME_ITS_TRUE(true);
    }
}

FOSSIL_TEST_CASE(cpp_test_keygen_compute_unsupported_base) {
    // Unsupported base should throw
    try {
        fossil::cryptic::Keygen::compute("fnv", "u32", "octal", "seed");
        ASSUME_ITS_TRUE(false);
    } catch (const std::runtime_error&) {
        ASSUME_ITS_TRUE(true);
    }
}

// * * * * * * * * * * * * * * * * * * * * * * * *
// * Fossil Logic Test Pool
// * * * * * * * * * * * * * * * * * * * * * * * *
FOSSIL_TEST_GROUP(cpp_keygen_tests) {
    FOSSIL_TEST_ADD(cpp_keygen_fixture, cpp_test_keygen_compute_basicpp_fnv_hex_u32);
    FOSSIL_TEST_ADD(cpp_keygen_fixture, cpp_test_keygen_compute_basicpp_fnv_hex_u64);
    FOSSIL_TEST_ADD(cpp_keygen_fixture, cpp_test_keygen_compute_crcpp_base64_u32);
    FOSSIL_TEST_ADD(cpp_keygen_fixture, cpp_test_keygen_compute_mix_auto_auto);
    FOSSIL_TEST_ADD(cpp_keygen_fixture, cpp_test_keygen_compute_null_arguments);
    FOSSIL_TEST_ADD(cpp_keygen_fixture, cpp_test_keygen_compute_unsupported_algorithm);
    FOSSIL_TEST_ADD(cpp_keygen_fixture, cpp_test_keygen_compute_unsupported_base);

    FOSSIL_TEST_REGISTER(cpp_keygen_fixture);
} // end of tests
