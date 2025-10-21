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

FOSSIL_TEST_SUITE(c_sign_fixture);

FOSSIL_SETUP(c_sign_fixture) {
    // Setup the test fixture
}

FOSSIL_TEARDOWN(c_sign_fixture) {
    // Teardown the test fixture
}

// * * * * * * * * * * * * * * * * * * * * * * * *
// * Fossil Logic Test Cases
// * * * * * * * * * * * * * * * * * * * * * * * *
// The test cases below are provided as samples, inspired
// by the Meson build system's approach of using test cases
// as samples for library usage.
// * * * * * * * * * * * * * * * * * * * * * * * *

FOSSIL_TEST_CASE(c_test_sign_signature_no_timestamp) {
    // Should sign input without timestamp ("none" or "")
    const char *algorithm = "hmac-sha256";
    const char *bits = "u64";
    const char *base = "hex";
    const char *key = "secret";
    const char *input = "Hello Fossil";
    char output[512];

    // Test with "none"
    int rc = fossil_cryptic_sign(
        algorithm, bits, base, key,
        input, strlen(input),
        "none",
        output, sizeof(output)
    );
    ASSUME_ITS_EQUAL_I32(rc, 0);
    ASSUME_ITS_TRUE(strlen(output) > 0);
    ASSUME_ITS_TRUE(strchr(output, ':') == NULL);

    int ok = 0;
    rc = fossil_cryptic_check(
        algorithm, bits, base, key,
        input, strlen(input),
        output,
        &ok
    );
    ASSUME_ITS_EQUAL_I32(rc, 0);
    ASSUME_ITS_EQUAL_I32(ok, 1);

    // Test with ""
    rc = fossil_cryptic_sign(
        algorithm, bits, base, key,
        input, strlen(input),
        "",
        output, sizeof(output)
    );
    ASSUME_ITS_EQUAL_I32(rc, 0);
    ASSUME_ITS_TRUE(strlen(output) > 0);
    ASSUME_ITS_TRUE(strchr(output, ':') == NULL);

    rc = fossil_cryptic_check(
        algorithm, bits, base, key,
        input, strlen(input),
        output,
        &ok
    );
    ASSUME_ITS_EQUAL_I32(rc, 0);
    ASSUME_ITS_EQUAL_I32(ok, 1);
}

FOSSIL_TEST_CASE(c_test_sign_signature_with_auto_timestamp) {
    // Should sign input with auto timestamp ("auto" or NULL)
    const char *algorithm = "hmac-sha256";
    const char *bits = "u64";
    const char *base = "hex";
    const char *key = "secret";
    const char *input = "Hello Fossil";
    char output[512];

    // Test with "auto"
    int rc = fossil_cryptic_sign(
        algorithm, bits, base, key,
        input, strlen(input),
        "auto",
        output, sizeof(output)
    );
    ASSUME_ITS_EQUAL_I32(rc, 0);
    ASSUME_ITS_TRUE(strlen(output) > 0);
    char *colon = strchr(output, ':');
    ASSUME_ITS_TRUE(colon != NULL);

    int ok = 0;
    rc = fossil_cryptic_check(
        algorithm, bits, base, key,
        input, strlen(input),
        output,
        &ok
    );
    ASSUME_ITS_EQUAL_I32(rc, 0);
    ASSUME_ITS_EQUAL_I32(ok, 1);

    // Test with NULL
    rc = fossil_cryptic_sign(
        algorithm, bits, base, key,
        input, strlen(input),
        NULL,
        output, sizeof(output)
    );
    ASSUME_ITS_EQUAL_I32(rc, 0);
    ASSUME_ITS_TRUE(strlen(output) > 0);
    colon = strchr(output, ':');
    ASSUME_ITS_TRUE(colon != NULL);

    rc = fossil_cryptic_check(
        algorithm, bits, base, key,
        input, strlen(input),
        output,
        &ok
    );
    ASSUME_ITS_EQUAL_I32(rc, 0);
    ASSUME_ITS_EQUAL_I32(ok, 1);
}

FOSSIL_TEST_CASE(c_test_sign_signature_with_explicit_timestamp) {
    // Should sign input with explicit timestamp
    const char *algorithm = "hmac-sha256";
    const char *bits = "u64";
    const char *base = "hex";
    const char *key = "secret";
    const char *input = "Hello Fossil";
    const char *timestamp = "1234567890";
    char output[512];

    int rc = fossil_cryptic_sign(
        algorithm, bits, base, key,
        input, strlen(input),
        timestamp,
        output, sizeof(output)
    );
    ASSUME_ITS_EQUAL_I32(rc, 0);
    ASSUME_ITS_TRUE(strlen(output) > 0);
    ASSUME_ITS_TRUE(strncmp(output, timestamp, strlen(timestamp)) == 0);
    ASSUME_ITS_TRUE(strchr(output, ':') != NULL);

    int ok = 0;
    rc = fossil_cryptic_check(
        algorithm, bits, base, key,
        input, strlen(input),
        output,
        &ok
    );
    ASSUME_ITS_EQUAL_I32(rc, 0);
    ASSUME_ITS_EQUAL_I32(ok, 1);
}

FOSSIL_TEST_CASE(c_test_sign_null_arguments) {
    // Should fail with null or invalid arguments
    char output[128];
    int rc = fossil_cryptic_sign(NULL, "u64", "hex", "key", "data", 4, "none", output, sizeof(output));
    ASSUME_ITS_TRUE(rc < 0);

    rc = fossil_cryptic_sign("hmac-sha256", NULL, "hex", "key", "data", 4, "none", output, sizeof(output));
    ASSUME_ITS_TRUE(rc < 0);

    rc = fossil_cryptic_sign("hmac-sha256", "u64", NULL, "key", "data", 4, "none", output, sizeof(output));
    ASSUME_ITS_TRUE(rc < 0);

    rc = fossil_cryptic_sign("hmac-sha256", "u64", "hex", NULL, "data", 4, "none", output, sizeof(output));
    ASSUME_ITS_TRUE(rc < 0);

    rc = fossil_cryptic_sign("hmac-sha256", "u64", "hex", "key", NULL, 4, "none", output, sizeof(output));
    ASSUME_ITS_TRUE(rc < 0);

    rc = fossil_cryptic_sign("hmac-sha256", "u64", "hex", "key", "data", 4, "none", NULL, sizeof(output));
    ASSUME_ITS_TRUE(rc < 0);
}

FOSSIL_TEST_CASE(c_test_check_valid_signature_no_timestamp) {
    // Should verify signature with no timestamp
    const char *algorithm = "hmac-sha256";
    const char *bits = "u64";
    const char *base = "hex";
    const char *key = "secret";
    const char *input = "Hello Fossil";
    char signature[512];
    int ok = 0;

    int rc = fossil_cryptic_sign(
        algorithm, bits, base, key,
        input, strlen(input),
        "none",
        signature, sizeof(signature)
    );
    ASSUME_ITS_EQUAL_I32(rc, 0);

    rc = fossil_cryptic_check(
        algorithm, bits, base, key,
        input, strlen(input),
        signature,
        &ok
    );
    ASSUME_ITS_EQUAL_I32(rc, 0);
    ASSUME_ITS_EQUAL_I32(ok, 1);
}

FOSSIL_TEST_CASE(c_test_check_invalid_signature) {
    // Should detect invalid signature
    const char *algorithm = "hmac-sha256";
    const char *bits = "u64";
    const char *base = "hex";
    const char *key = "secret";
    const char *input = "Hello Fossil";
    char signature[512];
    int ok = 0;

    int rc = fossil_cryptic_sign(
        algorithm, bits, base, key,
        input, strlen(input),
        "none",
        signature, sizeof(signature)
    );
    ASSUME_ITS_EQUAL_I32(rc, 0);

    // Tamper signature
    signature[0] = (signature[0] == 'a') ? 'b' : 'a';

    rc = fossil_cryptic_check(
        algorithm, bits, base, key,
        input, strlen(input),
        signature,
        &ok
    );
    ASSUME_ITS_EQUAL_I32(rc, 1);
    ASSUME_ITS_EQUAL_I32(ok, 0);
}

FOSSIL_TEST_CASE(c_test_check_valid_signature_with_explicit_timestamp) {
    // Should verify signature with explicit timestamp
    const char *algorithm = "hmac-sha256";
    const char *bits = "u64";
    const char *base = "hex";
    const char *key = "secret";
    const char *input = "Hello Fossil";
    const char *timestamp = "1234567890";
    char signature[512];
    int ok = 0;

    int rc = fossil_cryptic_sign(
        algorithm, bits, base, key,
        input, strlen(input),
        timestamp,
        signature, sizeof(signature)
    );
    ASSUME_ITS_EQUAL_I32(rc, 0);

    rc = fossil_cryptic_check(
        algorithm, bits, base, key,
        input, strlen(input),
        signature,
        &ok
    );
    ASSUME_ITS_EQUAL_I32(rc, 0);
    ASSUME_ITS_EQUAL_I32(ok, 1);
}

// * * * * * * * * * * * * * * * * * * * * * * * *
// * Fossil Logic Test Pool
// * * * * * * * * * * * * * * * * * * * * * * * *
FOSSIL_TEST_GROUP(c_sign_tests) {
    FOSSIL_TEST_ADD(c_sign_fixture, c_test_sign_signature_no_timestamp);
    FOSSIL_TEST_ADD(c_sign_fixture, c_test_sign_signature_with_auto_timestamp);
    FOSSIL_TEST_ADD(c_sign_fixture, c_test_sign_signature_with_explicit_timestamp);
    FOSSIL_TEST_ADD(c_sign_fixture, c_test_sign_null_arguments);
    FOSSIL_TEST_ADD(c_sign_fixture, c_test_check_valid_signature_no_timestamp);
    FOSSIL_TEST_ADD(c_sign_fixture, c_test_check_invalid_signature);
    FOSSIL_TEST_ADD(c_sign_fixture, c_test_check_valid_signature_with_explicit_timestamp);

    FOSSIL_TEST_REGISTER(c_sign_fixture);
} // end of tests
