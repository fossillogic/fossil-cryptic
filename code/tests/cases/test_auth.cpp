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

FOSSIL_TEST_SUITE(cpp_auth_fixture);

FOSSIL_SETUP(cpp_auth_fixture) {
    // Setup the test fixture
}

FOSSIL_TEARDOWN(cpp_auth_fixture) {
    // Teardown the test fixture
}

// * * * * * * * * * * * * * * * * * * * * * * * *
// * Fossil Logic Test Cases
// * * * * * * * * * * * * * * * * * * * * * * * *
// The test cases below are provided as samples, inspired
// by the Meson build system's approach of using test cases
// as samples for library usage.
// * * * * * * * * * * * * * * * * * * * * * * * *

FOSSIL_TEST_CASE(cpp_test_auth_compute_null_params) {
    // Should fail with any null parameter
    char output[128];
    int rc;

    rc = fossil_cryptic_auth_compute(NULL, "u64", "hex", "key", "data", 4, output, sizeof(output));
    ASSUME_ITS_EQUAL_I32(rc, -1);

    rc = fossil_cryptic_auth_compute("hmac-sha256", NULL, "hex", "key", "data", 4, output, sizeof(output));
    ASSUME_ITS_EQUAL_I32(rc, -1);

    rc = fossil_cryptic_auth_compute("hmac-sha256", "u64", NULL, "key", "data", 4, output, sizeof(output));
    ASSUME_ITS_EQUAL_I32(rc, -1);

    rc = fossil_cryptic_auth_compute("hmac-sha256", "u64", "hex", NULL, "data", 4, output, sizeof(output));
    ASSUME_ITS_EQUAL_I32(rc, -1);

    rc = fossil_cryptic_auth_compute("hmac-sha256", "u64", "hex", "key", NULL, 4, output, sizeof(output));
    ASSUME_ITS_EQUAL_I32(rc, -1);

    rc = fossil_cryptic_auth_compute("hmac-sha256", "u64", "hex", "key", "data", 4, NULL, sizeof(output));
    ASSUME_ITS_EQUAL_I32(rc, -1);
}

FOSSIL_TEST_CASE(cpp_test_auth_compute_output_buffer_too_small) {
    // Output buffer too small should fail
    const char *algorithm = "hmac-sha256";
    const char *bits = "u64";
    const char *base = "hex";
    const char *key = "key";
    const char *input = "input";
    char output[1];

    int rc = fossil_cryptic_auth_compute(
        algorithm, bits, base,
        key,
        input, strlen(input),
        output, sizeof(output)
    );
    ASSUME_ITS_TRUE(rc != 0);
}

FOSSIL_TEST_CASE(cpp_test_auth_compute_invalid_algorithm) {
    // Invalid algorithm should fail
    const char *algorithm = "invalid-algo";
    const char *bits = "u64";
    const char *base = "hex";
    const char *key = "key";
    const char *input = "input";
    char output[128];

    int rc = fossil_cryptic_auth_compute(
        algorithm, bits, base,
        key,
        input, strlen(input),
        output, sizeof(output)
    );
    ASSUME_ITS_TRUE(rc != 0);
}

FOSSIL_TEST_CASE(cpp_test_auth_compute_invalid_bits) {
    // Invalid bits should fail
    const char *algorithm = "hmac-sha256";
    const char *bits = "invalid-bits";
    const char *base = "hex";
    const char *key = "key";
    const char *input = "input";
    char output[128];

    int rc = fossil_cryptic_auth_compute(
        algorithm, bits, base,
        key,
        input, strlen(input),
        output, sizeof(output)
    );
    ASSUME_ITS_TRUE(rc != 0);
}

FOSSIL_TEST_CASE(cpp_test_auth_compute_invalid_base) {
    // Invalid base should fail
    const char *algorithm = "hmac-sha256";
    const char *bits = "u64";
    const char *base = "invalid-base";
    const char *key = "key";
    const char *input = "input";
    char output[128];

    int rc = fossil_cryptic_auth_compute(
        algorithm, bits, base,
        key,
        input, strlen(input),
        output, sizeof(output)
    );
    ASSUME_ITS_TRUE(rc != 0);
}


// * * * * * * * * * * * * * * * * * * * * * * * *
// * Fossil Logic Test Pool
// * * * * * * * * * * * * * * * * * * * * * * * *
FOSSIL_TEST_GROUP(cpp_auth_tests) {
    FOSSIL_TEST_ADD(cpp_auth_fixture, cpp_test_auth_compute_null_params);
    FOSSIL_TEST_ADD(cpp_auth_fixture, cpp_test_auth_compute_output_buffer_too_small);
    FOSSIL_TEST_ADD(cpp_auth_fixture, cpp_test_auth_compute_invalid_algorithm);
    FOSSIL_TEST_ADD(cpp_auth_fixture, cpp_test_auth_compute_invalid_bits);
    FOSSIL_TEST_ADD(cpp_auth_fixture, cpp_test_auth_compute_invalid_base);

    FOSSIL_TEST_REGISTER(cpp_auth_fixture);
} // end of tests
