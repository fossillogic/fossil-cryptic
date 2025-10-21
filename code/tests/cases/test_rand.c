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

FOSSIL_TEST_SUITE(c_rand_fixture);

FOSSIL_SETUP(c_rand_fixture) {
    // Setup the test fixture
}

FOSSIL_TEARDOWN(c_rand_fixture) {
    // Teardown the test fixture
}

// * * * * * * * * * * * * * * * * * * * * * * * *
// * Fossil Logic Test Cases
// * * * * * * * * * * * * * * * * * * * * * * * *
// The test cases below are provided as samples, inspired
// by the Meson build system's approach of using test cases
// as samples for library usage.
// * * * * * * * * * * * * * * * * * * * * * * * *

FOSSIL_TEST_CASE(c_test_rand_compute_basic_lcg_hex_u32) {
    // Basic LCG, hex, u32
    char output[32];
    int rc = fossil_cryptic_rand_compute("lcg", "u32", "hex", "seed123", output, sizeof(output));
    ASSUME_ITS_EQUAL_I32(rc, 0);
    ASSUME_ITS_TRUE(strlen(output) == 8); // 8 hex digits for u32
}

FOSSIL_TEST_CASE(c_test_rand_compute_basic_lcg_hex_u64) {
    // Basic LCG, hex, u64
    char output[32];
    int rc = fossil_cryptic_rand_compute("lcg", "u64", "hex", "seed456", output, sizeof(output));
    ASSUME_ITS_EQUAL_I32(rc, 0);
    ASSUME_ITS_TRUE(strlen(output) == 16); // 16 hex digits for u64
}

FOSSIL_TEST_CASE(c_test_rand_compute_xor_base64_u32) {
    // XOR, base64, u32
    char output[32];
    int rc = fossil_cryptic_rand_compute("xor", "u32", "base64", "seed789", output, sizeof(output));
    ASSUME_ITS_EQUAL_I32(rc, 0);
    ASSUME_ITS_TRUE(strlen(output) >= 6); // base64 for 4 bytes
}

FOSSIL_TEST_CASE(c_test_rand_compute_mix_base64_u64) {
    // Mix, base64, u64
    char output[32];
    int rc = fossil_cryptic_rand_compute("mix", "u64", "base64", "seedABC", output, sizeof(output));
    ASSUME_ITS_EQUAL_I32(rc, 0);
    ASSUME_ITS_TRUE(strlen(output) >= 11); // base64 for 8 bytes
}

FOSSIL_TEST_CASE(c_test_rand_compute_auto_params) {
    // All "auto" parameters
    char output[32];
    int rc = fossil_cryptic_rand_compute("auto", "auto", "auto", NULL, output, sizeof(output));
    ASSUME_ITS_EQUAL_I32(rc, 0);
    ASSUME_ITS_TRUE(strlen(output) > 0);
}

FOSSIL_TEST_CASE(c_test_rand_compute_null_arguments) {
    // Should fail with null arguments
    char output[32];
    ASSUME_ITS_EQUAL_I32(fossil_cryptic_rand_compute(NULL, "u32", "hex", "seed", output, sizeof(output)), -1);
    ASSUME_ITS_EQUAL_I32(fossil_cryptic_rand_compute("lcg", NULL, "hex", "seed", output, sizeof(output)), -1);
    ASSUME_ITS_EQUAL_I32(fossil_cryptic_rand_compute("lcg", "u32", NULL, "seed", output, sizeof(output)), -1);
    ASSUME_ITS_EQUAL_I32(fossil_cryptic_rand_compute("lcg", "u32", "hex", "seed", NULL, sizeof(output)), -1);
}

FOSSIL_TEST_CASE(c_test_rand_compute_unsupported_algorithm) {
    // Unsupported algorithm
    char output[32];
    int rc = fossil_cryptic_rand_compute("unknown", "u32", "hex", "seed", output, sizeof(output));
    ASSUME_ITS_EQUAL_I32(rc, -2);
}

FOSSIL_TEST_CASE(c_test_rand_compute_unsupported_base) {
    // Unsupported base
    char output[32];
    int rc = fossil_cryptic_rand_compute("lcg", "u32", "octal", "seed", output, sizeof(output));
    ASSUME_ITS_EQUAL_I32(rc, -3);
}

// * * * * * * * * * * * * * * * * * * * * * * * *
// * Fossil Logic Test Pool
// * * * * * * * * * * * * * * * * * * * * * * * *
FOSSIL_TEST_GROUP(c_rand_tests) {
    FOSSIL_TEST_ADD(c_rand_fixture, c_test_rand_compute_basic_lcg_hex_u32);
    FOSSIL_TEST_ADD(c_rand_fixture, c_test_rand_compute_basic_lcg_hex_u64);
    FOSSIL_TEST_ADD(c_rand_fixture, c_test_rand_compute_xor_base64_u32);
    FOSSIL_TEST_ADD(c_rand_fixture, c_test_rand_compute_mix_base64_u64);
    FOSSIL_TEST_ADD(c_rand_fixture, c_test_rand_compute_auto_params);
    FOSSIL_TEST_ADD(c_rand_fixture, c_test_rand_compute_null_arguments);
    FOSSIL_TEST_ADD(c_rand_fixture, c_test_rand_compute_unsupported_algorithm);
    FOSSIL_TEST_ADD(c_rand_fixture, c_test_rand_compute_unsupported_base);

    FOSSIL_TEST_REGISTER(c_rand_fixture);
} // end of tests
