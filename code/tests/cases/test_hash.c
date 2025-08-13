/*
 * -----------------------------------------------------------------------------
 * Project: Fossil Logic
 *
 * This file is part of the Fossil Logic project, which aims to develop high-
 * performance, cross-platform applications and libraries. The code contained
 * herein is subject to the terms and conditions defined in the project license.
 *
 * Author: Michael Gene Brockus (Dreamer)
 *
 * Copyright (C) 2024 Fossil Logic. All rights reserved.
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

FOSSIL_TEST_SUITE(c_hash_fixture);

FOSSIL_SETUP(c_hash_fixture) {
    // Setup the test fixture
}

FOSSIL_TEARDOWN(c_hash_fixture) {
    // Teardown the test fixture
}

// * * * * * * * * * * * * * * * * * * * * * * * *
// * Fossil Logic Test Cases
// * * * * * * * * * * * * * * * * * * * * * * * *
// The test cases below are provided as samples, inspired
// by the Meson build system's approach of using test cases
// as samples for library usage.
// * * * * * * * * * * * * * * * * * * * * * * * *

FOSSIL_TEST_CASE(c_test_sha256_oneshot) {
    const char *msg = "abc";
    uint8_t hash[32];
    char hex[65];
    fossil_cryptic_hash_sha256(msg, 3, hash);
    fossil_cryptic_hash_sha256_to_hex(hash, hex);
    ASSUME_ITS_EQUAL_CSTR(hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

FOSSIL_TEST_CASE(c_test_sha256_streaming) {
    const char *msg = "abc";
    uint8_t hash[32];
    char hex[65];
    fossil_cryptic_hash_sha256_ctx_t ctx;
    fossil_cryptic_hash_sha256_init(&ctx);
    fossil_cryptic_hash_sha256_update(&ctx, msg, 3);
    fossil_cryptic_hash_sha256_final(&ctx, hash);
    fossil_cryptic_hash_sha256_to_hex(hash, hex);
    ASSUME_ITS_EQUAL_CSTR(hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

FOSSIL_TEST_CASE(c_test_crc32_oneshot) {
    const char *msg = "abc";
    uint32_t crc = fossil_cryptic_hash_crc32(msg, 3);
    char hex[9];
    fossil_cryptic_hash_u32_to_hex(crc, hex);
    ASSUME_ITS_EQUAL_CSTR(hex, "352441c2");
}

FOSSIL_TEST_CASE(c_test_fnv1a32_oneshot) {
    const char *msg = "abc";
    uint32_t fnv = fossil_cryptic_hash_fnv1a32(msg, 3);
    char hex[9];
    fossil_cryptic_hash_u32_to_hex(fnv, hex);
    ASSUME_ITS_EQUAL_CSTR(hex, "e40c292c");
}

FOSSIL_TEST_CASE(c_test_fnv1a64_oneshot) {
    const char *msg = "abc";
    uint64_t fnv = fossil_cryptic_hash_fnv1a64(msg, 3);
    char hex[17];
    fossil_cryptic_hash_u64_to_hex(fnv, hex);
    ASSUME_ITS_EQUAL_CSTR(hex, "af63dc4c8601ec8c");
}

FOSSIL_TEST_CASE(c_test_murmur3_oneshot) {
    const char *msg = "abc";
    uint32_t mm3 = fossil_cryptic_hash_murmur3_32(msg, 3, 0);
    char hex[9];
    fossil_cryptic_hash_u32_to_hex(mm3, hex);
    ASSUME_ITS_EQUAL_CSTR(hex, "b3dd93fa");
}

FOSSIL_TEST_CASE(c_test_streaming_crc32) {
    const char *msg = "abc";
    fossil_cryptic_hash_ctx_t ctx;
    fossil_cryptic_hash_init(&ctx, FOSSIL_CRYPTIC_HASH_ALG_CRC32);
    fossil_cryptic_hash_update(&ctx, msg, 3);
    uint32_t crc = fossil_cryptic_hash_final32(&ctx);
    char hex[9];
    fossil_cryptic_hash_u32_to_hex(crc, hex);
    ASSUME_ITS_EQUAL_CSTR(hex, "352441c2");
}

FOSSIL_TEST_CASE(c_test_streaming_fnv1a32) {
    const char *msg = "abc";
    fossil_cryptic_hash_ctx_t ctx;
    fossil_cryptic_hash_init(&ctx, FOSSIL_CRYPTIC_HASH_ALG_FNV1A32);
    fossil_cryptic_hash_update(&ctx, msg, 3);
    uint32_t fnv = fossil_cryptic_hash_final32(&ctx);
    char hex[9];
    fossil_cryptic_hash_u32_to_hex(fnv, hex);
    ASSUME_ITS_EQUAL_CSTR(hex, "e40c292c");
}

FOSSIL_TEST_CASE(c_test_streaming_fnv1a64) {
    const char *msg = "abc";
    fossil_cryptic_hash_ctx_t ctx;
    fossil_cryptic_hash_init(&ctx, FOSSIL_CRYPTIC_HASH_ALG_FNV1A64);
    fossil_cryptic_hash_update(&ctx, msg, 3);
    uint64_t fnv = fossil_cryptic_hash_final64(&ctx);
    char hex[17];
    fossil_cryptic_hash_u64_to_hex(fnv, hex);
    ASSUME_ITS_EQUAL_CSTR(hex, "af63dc4c8601ec8c");
}

FOSSIL_TEST_CASE(c_test_streaming_sha256_generic) {
    const char *msg = "abc";
    fossil_cryptic_hash_ctx_t ctx;
    uint8_t hash[32];
    char hex[65];
    fossil_cryptic_hash_init(&ctx, FOSSIL_CRYPTIC_HASH_ALG_SHA256);
    fossil_cryptic_hash_update(&ctx, msg, 3);
    fossil_cryptic_hash_final_sha256(&ctx, hash);
    fossil_cryptic_hash_sha256_to_hex(hash, hex);
    ASSUME_ITS_EQUAL_CSTR(hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

// * * * * * * * * * * * * * * * * * * * * * * * *
// * Fossil Logic Test Pool
// * * * * * * * * * * * * * * * * * * * * * * * *
FOSSIL_TEST_GROUP(c_hash_tests) {
    FOSSIL_TEST_ADD(c_hash_fixture, c_test_sha256_oneshot);
    FOSSIL_TEST_ADD(c_hash_fixture, c_test_sha256_streaming);
    FOSSIL_TEST_ADD(c_hash_fixture, c_test_crc32_oneshot);
    FOSSIL_TEST_ADD(c_hash_fixture, c_test_fnv1a32_oneshot);
    FOSSIL_TEST_ADD(c_hash_fixture, c_test_fnv1a64_oneshot);
    FOSSIL_TEST_ADD(c_hash_fixture, c_test_murmur3_oneshot);
    FOSSIL_TEST_ADD(c_hash_fixture, c_test_streaming_crc32);
    FOSSIL_TEST_ADD(c_hash_fixture, c_test_streaming_fnv1a32);
    FOSSIL_TEST_ADD(c_hash_fixture, c_test_streaming_fnv1a64);
    FOSSIL_TEST_ADD(c_hash_fixture, c_test_streaming_sha256_generic);

    FOSSIL_TEST_REGISTER(c_hash_fixture);
} // end of tests
