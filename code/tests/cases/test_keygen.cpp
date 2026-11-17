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

FOSSIL_SUITE(cpp_keygen_fixture);

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

FOSSIL_TEST(cpp_test_keygen_hkdf_sha256) {
    const uint8_t ikm[] = {0x0b, 0x0b, 0x0b, 0x0b};
    const uint8_t salt[] = {0x00, 0x01, 0x02, 0x03};
    const uint8_t info[] = {0xf0, 0xf1, 0xf2};

    const auto key = fossil::cryptic::Keygen::hkdf_sha256(
        ikm, sizeof(ikm), salt, sizeof(salt), info, sizeof(info), 32);
    const auto repeated_key = fossil::cryptic::Keygen::hkdf_sha256(
        ikm, sizeof(ikm), salt, sizeof(salt), info, sizeof(info), 32);

    ASSUME_ITS_TRUE(key.size() == 32);
    ASSUME_ITS_TRUE(key == repeated_key);
}

FOSSIL_TEST(cpp_test_keygen_pbkdf2_sha256) {
    const uint8_t password[] = {'p', 'a', 's', 's'};
    const uint8_t salt[] = {'s', 'a', 'l', 't'};

    const auto key = fossil::cryptic::Keygen::pbkdf2_sha256(
        password, sizeof(password), salt, sizeof(salt), 1000, 32);
    const auto repeated_key = fossil::cryptic::Keygen::pbkdf2_sha256(
        password, sizeof(password), salt, sizeof(salt), 1000, 32);

    ASSUME_ITS_TRUE(key.size() == 32);
    ASSUME_ITS_TRUE(key == repeated_key);
}

// * * * * * * * * * * * * * * * * * * * * * * * *
// * Fossil Logic Test Pool
// * * * * * * * * * * * * * * * * * * * * * * * *
FOSSIL_TEST_GROUP(cpp_keygen_tests) {
    FOSSIL_ADD_TEST(cpp_keygen_fixture, cpp_test_keygen_hkdf_sha256);
    FOSSIL_ADD_TEST(cpp_keygen_fixture, cpp_test_keygen_pbkdf2_sha256);

    FOSSIL_ADD_SUITE(cpp_keygen_fixture);
} // end of tests
