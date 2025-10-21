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

FOSSIL_TEST_SUITE(c_keygen_fixture);

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

FOSSIL_TEST_CASE(c_test_keygen_compute_basic_fnv_hex_u32) {
    // Basic FNV keygen, hex, u32
    char output[32];
    int rc = fossil_cryptic_keygen_compute("fnv", "u32", "hex", "hello", output, sizeof(output));
    ASSUME_ITS_EQUAL_I32(rc, 0);
    ASSUME_ITS_TRUE(strlen(output) == 8); // 8 hex digits for u32
}

FOSSIL_TEST_CASE(c_test_keygen_compute_basic_fnv_hex_u64) {
    // Basic FNV keygen, hex, u64
    char output[32];
    int rc = fossil_cryptic_keygen_compute("fnv", "u64", "hex", "hello", output, sizeof(output));
    ASSUME_ITS_EQUAL_I32(rc, 0);
    ASSUME_ITS_TRUE(strlen(output) == 16); // 16 hex digits for u64
}

FOSSIL_TEST_CASE(c_test_keygen_compute_crc_base64_u32) {
    // CRC keygen, base64, u32
    char output[32];
    int rc = fossil_cryptic_keygen_compute("crc", "u32", "base64", "seed", output, sizeof(output));
    ASSUME_ITS_EQUAL_I32(rc, 0);
    ASSUME_ITS_TRUE(strlen(output) > 0);
}

FOSSIL_TEST_CASE(c_test_keygen_compute_mix_auto_auto) {
    // Mix algorithm, auto bits, auto base
    char output[32];
    int rc = fossil_cryptic_keygen_compute("mix", "auto", "auto", "longseedvalue", output, sizeof(output));
    ASSUME_ITS_EQUAL_I32(rc, 0);
    ASSUME_ITS_TRUE(strlen(output) > 0);
}

FOSSIL_TEST_CASE(c_test_keygen_compute_null_arguments) {
    // Should fail with null arguments
    char output[32];
    ASSUME_ITS_TRUE(fossil_cryptic_keygen_compute(NULL, "u32", "hex", "seed", output, sizeof(output)) != 0);
    ASSUME_ITS_TRUE(fossil_cryptic_keygen_compute("fnv", NULL, "hex", "seed", output, sizeof(output)) != 0);
    ASSUME_ITS_TRUE(fossil_cryptic_keygen_compute("fnv", "u32", NULL, "seed", output, sizeof(output)) != 0);
    ASSUME_ITS_TRUE(fossil_cryptic_keygen_compute("fnv", "u32", "hex", NULL, output, sizeof(output)) != 0);
    ASSUME_ITS_TRUE(fossil_cryptic_keygen_compute("fnv", "u32", "hex", "seed", NULL, sizeof(output)) != 0);
}

FOSSIL_TEST_CASE(c_test_keygen_compute_unsupported_algorithm) {
    // Unsupported algorithm should fail
    char output[32];
    int rc = fossil_cryptic_keygen_compute("unknown", "u32", "hex", "seed", output, sizeof(output));
    ASSUME_ITS_TRUE(rc != 0);
}

FOSSIL_TEST_CASE(c_test_keygen_compute_unsupported_base) {
    // Unsupported base should fail
    char output[32];
    int rc = fossil_cryptic_keygen_compute("fnv", "u32", "octal", "seed", output, sizeof(output));
    ASSUME_ITS_TRUE(rc != 0);
}

FOSSIL_TEST_CASE(c_test_keygen_compute_output_buffer_too_small) {
    // Output buffer too small should fail
    char output[1];
    int rc = fossil_cryptic_keygen_compute("fnv", "u64", "hex", "seed", output, sizeof(output));
    ASSUME_ITS_TRUE(rc != 0);
}

// * * * * * * * * * * * * * * * * * * * * * * * *
// * Fossil Logic Test Pool
// * * * * * * * * * * * * * * * * * * * * * * * *
FOSSIL_TEST_GROUP(c_keygen_tests) {
    FOSSIL_TEST_ADD(c_keygen_fixture, c_test_keygen_compute_basic_fnv_hex_u32);
    FOSSIL_TEST_ADD(c_keygen_fixture, c_test_keygen_compute_basic_fnv_hex_u64);
    FOSSIL_TEST_ADD(c_keygen_fixture, c_test_keygen_compute_crc_base64_u32);
    FOSSIL_TEST_ADD(c_keygen_fixture, c_test_keygen_compute_mix_auto_auto);
    FOSSIL_TEST_ADD(c_keygen_fixture, c_test_keygen_compute_null_arguments);
    FOSSIL_TEST_ADD(c_keygen_fixture, c_test_keygen_compute_unsupported_algorithm);
    FOSSIL_TEST_ADD(c_keygen_fixture, c_test_keygen_compute_unsupported_base);
    FOSSIL_TEST_ADD(c_keygen_fixture, c_test_keygen_compute_output_buffer_too_small);

    FOSSIL_TEST_REGISTER(c_keygen_fixture);
} // end of tests
