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

FOSSIL_TEST_SUITE(cpp_rand_fixture);

FOSSIL_SETUP(cpp_rand_fixture) {
    // Setup the test fixture
}

FOSSIL_TEARDOWN(cpp_rand_fixture) {
    // Teardown the test fixture
}

// * * * * * * * * * * * * * * * * * * * * * * * *
// * Fossil Logic Test Cases
// * * * * * * * * * * * * * * * * * * * * * * * *
// The test cases below are provided as samples, inspired
// by the Meson build system's approach of using test cases
// as samples for library usage.
// * * * * * * * * * * * * * * * * * * * * * * * *

FOSSIL_TEST_CASE(cpp_test_rand_compute_basicpp_lcg_hex_u32) {
    // Basic LCG, hex, u32
    std::string output = fossil::cryptic::Rand::compute("lcg", "u32", "hex", "seed123");
    ASSUME_ITS_TRUE(output.length() == 8); // 8 hex digits for u32
}

FOSSIL_TEST_CASE(cpp_test_rand_compute_basicpp_lcg_hex_u64) {
    // Basic LCG, hex, u64
    std::string output = fossil::cryptic::Rand::compute("lcg", "u64", "hex", "seed456");
    ASSUME_ITS_TRUE(output.length() == 16); // 16 hex digits for u64
}

FOSSIL_TEST_CASE(cpp_test_rand_compute_xor_base64_u32) {
    // XOR, base64, u32
    std::string output = fossil::cryptic::Rand::compute("xor", "u32", "base64", "seed789");
    ASSUME_ITS_TRUE(output.length() >= 6); // base64 for 4 bytes
}

FOSSIL_TEST_CASE(cpp_test_rand_compute_mix_base64_u64) {
    // Mix, base64, u64
    std::string output = fossil::cryptic::Rand::compute("mix", "u64", "base64", "seedABC");
    ASSUME_ITS_TRUE(output.length() >= 11); // base64 for 8 bytes
}

FOSSIL_TEST_CASE(cpp_test_rand_compute_auto_params) {
    // All "auto" parameters
    std::string output = fossil::cryptic::Rand::compute("auto", "auto", "auto");
    ASSUME_ITS_TRUE(output.length() > 0);
}

FOSSIL_TEST_CASE(cpp_test_rand_compute_null_arguments) {
    // Should fail with null arguments
    try {
        fossil::cryptic::Rand::compute("", "u32", "hex", "seed");
        ASSUME_ITS_TRUE(false); // Should not reach here
    } catch (const std::exception&) {
        ASSUME_ITS_TRUE(true);
    }
    try {
        fossil::cryptic::Rand::compute("lcg", "", "hex", "seed");
        ASSUME_ITS_TRUE(false);
    } catch (const std::exception&) {
        ASSUME_ITS_TRUE(true);
    }
    try {
        fossil::cryptic::Rand::compute("lcg", "u32", "", "seed");
        ASSUME_ITS_TRUE(false);
    } catch (const std::exception&) {
        ASSUME_ITS_TRUE(true);
    }
}

FOSSIL_TEST_CASE(cpp_test_rand_compute_unsupported_algorithm) {
    // Unsupported algorithm
    try {
        fossil::cryptic::Rand::compute("unknown", "u32", "hex", "seed");
        ASSUME_ITS_TRUE(false);
    } catch (const std::exception&) {
        ASSUME_ITS_TRUE(true);
    }
}

FOSSIL_TEST_CASE(cpp_test_rand_compute_unsupported_base) {
    // Unsupported base
    try {
        fossil::cryptic::Rand::compute("lcg", "u32", "octal", "seed");
        ASSUME_ITS_TRUE(false);
    } catch (const std::exception&) {
        ASSUME_ITS_TRUE(true);
    }
}

// * * * * * * * * * * * * * * * * * * * * * * * *
// * Fossil Logic Test Pool
// * * * * * * * * * * * * * * * * * * * * * * * *
FOSSIL_TEST_GROUP(cpp_rand_tests) {
    FOSSIL_TEST_ADD(cpp_rand_fixture, cpp_test_rand_compute_basicpp_lcg_hex_u32);
    FOSSIL_TEST_ADD(cpp_rand_fixture, cpp_test_rand_compute_basicpp_lcg_hex_u64);
    FOSSIL_TEST_ADD(cpp_rand_fixture, cpp_test_rand_compute_xor_base64_u32);
    FOSSIL_TEST_ADD(cpp_rand_fixture, cpp_test_rand_compute_mix_base64_u64);
    FOSSIL_TEST_ADD(cpp_rand_fixture, cpp_test_rand_compute_auto_params);
    FOSSIL_TEST_ADD(cpp_rand_fixture, cpp_test_rand_compute_null_arguments);
    FOSSIL_TEST_ADD(cpp_rand_fixture, cpp_test_rand_compute_unsupported_algorithm);
    FOSSIL_TEST_ADD(cpp_rand_fixture, cpp_test_rand_compute_unsupported_base);

    FOSSIL_TEST_REGISTER(cpp_rand_fixture);
} // end of tests
