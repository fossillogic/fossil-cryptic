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

FOSSIL_SUITE(c_rand_fixture);

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

FOSSIL_TEST(c_test_rand_bytes_success) {
    // Generate cryptographically secure random bytes
    uint8_t output[32];
    int rc = fossil_cryptic_rand_bytes(output, sizeof(output));
    ASSUME_ITS_EQUAL_I32(rc, 0);
}

FOSSIL_TEST(c_test_rand_bytes_single_byte) {
    uint8_t output;
    int rc = fossil_cryptic_rand_bytes(&output, sizeof(output));
    ASSUME_ITS_EQUAL_I32(rc, 0);
}

FOSSIL_TEST(c_test_rand_bytes_large_buffer) {
    uint8_t output[256];
    int rc = fossil_cryptic_rand_bytes(output, sizeof(output));
    ASSUME_ITS_EQUAL_I32(rc, 0);
}

FOSSIL_TEST(c_test_rand_bytes_null_output) {
    // A non-empty request requires a valid output buffer
    ASSUME_ITS_TRUE(fossil_cryptic_rand_bytes(NULL, 1) < 0);
}

// * * * * * * * * * * * * * * * * * * * * * * * *
// * Fossil Logic Test Pool
// * * * * * * * * * * * * * * * * * * * * * * * *
FOSSIL_TEST_GROUP(c_rand_tests) {
    FOSSIL_ADD_TEST(c_rand_fixture, c_test_rand_bytes_success);
    FOSSIL_ADD_TEST(c_rand_fixture, c_test_rand_bytes_single_byte);
    FOSSIL_ADD_TEST(c_rand_fixture, c_test_rand_bytes_large_buffer);
    FOSSIL_ADD_TEST(c_rand_fixture, c_test_rand_bytes_null_output);

    FOSSIL_ADD_SUITE(c_rand_fixture);
} // end of tests
