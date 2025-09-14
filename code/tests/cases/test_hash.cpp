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

using fossil::cryptic::Hash;

FOSSIL_TEST_CASE(cpp_test_sha256_oneshot) {
    const char *msg = "abc";
    auto digest = Hash::sha256(msg, 3);
    auto hex = Hash::to_hex(digest);
    ASSUME_ITS_EQUAL_CSTR(hex.c_str(), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

FOSSIL_TEST_CASE(cpp_test_sha256_streaming) {
    const char *msg = "abc";
    Hash h(Hash::Algorithm::SHA256);
    h.update(msg, 3);
    auto digest = h.finalSHA256();
    auto hex = Hash::to_hex(digest);
    ASSUME_ITS_EQUAL_CSTR(hex.c_str(), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

FOSSIL_TEST_CASE(cpp_test_crc32_oneshot) {
    const char *msg = "abc";
    auto crc = Hash::crc32(msg, 3);
    auto hex = Hash::to_hex(crc);
    ASSUME_ITS_EQUAL_CSTR(hex.c_str(), "352441c2");
}

FOSSIL_TEST_CASE(cpp_test_fnv1a32_oneshot) {
    const char *msg = "abc";
    auto fnv = Hash::fnv1a32(msg, 3);
    auto hex = Hash::to_hex(fnv);
    ASSUME_ITS_EQUAL_CSTR(hex.c_str(), "e40c292c");
}

FOSSIL_TEST_CASE(cpp_test_fnv1a64_oneshot) {
    const char *msg = "abc";
    auto fnv = Hash::fnv1a64(msg, 3);
    auto hex = Hash::to_hex(fnv);
    ASSUME_ITS_EQUAL_CSTR(hex.c_str(), "af63dc4c8601ec8c");
}

FOSSIL_TEST_CASE(cpp_test_murmur3_oneshot) {
    const char *msg = "abc";
    auto mm3 = Hash::murmur3_32(msg, 3, 0);
    auto hex = Hash::to_hex(mm3);
    ASSUME_ITS_EQUAL_CSTR(hex.c_str(), "b3dd93fa");
}

FOSSIL_TEST_CASE(cpp_test_streaming_crc32) {
    const char *msg = "abc";
    Hash h(Hash::Algorithm::CRC32);
    h.update(msg, 3);
    auto crc = h.final32();
    auto hex = Hash::to_hex(crc);
    ASSUME_ITS_EQUAL_CSTR(hex.c_str(), "352441c2");
}

FOSSIL_TEST_CASE(cpp_test_streaming_fnv1a32) {
    const char *msg = "abc";
    Hash h(Hash::Algorithm::FNV1a32);
    h.update(msg, 3);
    auto fnv = h.final32();
    auto hex = Hash::to_hex(fnv);
    ASSUME_ITS_EQUAL_CSTR(hex.c_str(), "e40c292c");
}

FOSSIL_TEST_CASE(cpp_test_streaming_fnv1a64) {
    const char *msg = "abc";
    Hash h(Hash::Algorithm::FNV1a64);
    h.update(msg, 3);
    auto fnv = h.final64();
    auto hex = Hash::to_hex(fnv);
    ASSUME_ITS_EQUAL_CSTR(hex.c_str(), "af63dc4c8601ec8c");
}

FOSSIL_TEST_CASE(cpp_test_streaming_sha256_generic) {
    const char *msg = "abc";
    Hash h(Hash::Algorithm::SHA256);
    h.update(msg, 3);
    auto digest = h.finalSHA256();
    auto hex = Hash::to_hex(digest);
    ASSUME_ITS_EQUAL_CSTR(hex.c_str(), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

// * * * * * * * * * * * * * * * * * * * * * * * *
// * Fossil Logic Test Pool
// * * * * * * * * * * * * * * * * * * * * * * * *
FOSSIL_TEST_GROUP(cpp_hash_tests) {
    FOSSIL_TEST_ADD(cpp_hash_fixture, cpp_test_sha256_oneshot);
    FOSSIL_TEST_ADD(cpp_hash_fixture, cpp_test_sha256_streaming);
    FOSSIL_TEST_ADD(cpp_hash_fixture, cpp_test_crc32_oneshot);
    FOSSIL_TEST_ADD(cpp_hash_fixture, cpp_test_fnv1a32_oneshot);
    FOSSIL_TEST_ADD(cpp_hash_fixture, cpp_test_fnv1a64_oneshot);
    FOSSIL_TEST_ADD(cpp_hash_fixture, cpp_test_murmur3_oneshot);
    FOSSIL_TEST_ADD(cpp_hash_fixture, cpp_test_streaming_crc32);
    FOSSIL_TEST_ADD(cpp_hash_fixture, cpp_test_streaming_fnv1a32);
    FOSSIL_TEST_ADD(cpp_hash_fixture, cpp_test_streaming_fnv1a64);
    FOSSIL_TEST_ADD(cpp_hash_fixture, cpp_test_streaming_sha256_generic);

    FOSSIL_TEST_REGISTER(cpp_hash_fixture);
} // end of tests
