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

FOSSIL_TEST_SUITE(c_auth_fixture);

FOSSIL_SETUP(c_auth_fixture) {
    // Setup the test fixture
}

FOSSIL_TEARDOWN(c_auth_fixture) {
    // Teardown the test fixture
}

// * * * * * * * * * * * * * * * * * * * * * * * *
// * Fossil Logic Test Cases
// * * * * * * * * * * * * * * * * * * * * * * * *
// The test cases below are provided as samples, inspired
// by the Meson build system's approach of using test cases
// as samples for library usage.
// * * * * * * * * * * * * * * * * * * * * * * * *

FOSSIL_TEST_CASE(c_test_hmac_sha256_vectors) {
    // Test vector from RFC 4231, Test Case 1
    const uint8_t key[20] = {
        0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,
        0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b
    };
    const char *data = "Hi There";
    uint8_t mac[32];
    char hex[65];
    fossil_cryptic_auth_hmac_sha256(key, 20, (const uint8_t*)data, 8, mac);
    fossil_cryptic_hash_sha256_to_hex(mac, hex);
    ASSUME_ITS_EQUAL_CSTR(hex, "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
}

FOSSIL_TEST_CASE(c_test_pbkdf2_sha256_vector) {
    // Test vector from RFC 6070 (adapted for SHA256)
    const char *password = "password";
    const char *salt = "salt";
    uint8_t dk[32];
    char hex[65];
    fossil_cryptic_auth_pbkdf2_sha256(
        (const uint8_t*)password, 8,
        (const uint8_t*)salt, 4,
        1, dk, 32
    );
    fossil_cryptic_hash_sha256_to_hex(dk, hex);
    // Expected: 0c60c80f961f0e71f3a9b524af6012062fe037a6de5bfc1b2f8c2a5e6a5a5a08
    ASSUME_ITS_EQUAL_CSTR(hex, "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b");
}

FOSSIL_TEST_CASE(c_test_poly1305_oneshot_vector) {
    // Test vector from RFC 7539, Section 2.5.2
    const uint8_t key[32] = {
        0x85,0xd6,0xbe,0x78,0x57,0x55,0x6d,0x33,
        0x7f,0x44,0x52,0xfe,0x42,0xd5,0x06,0xa8,
        0x01,0x03,0x80,0x8a,0xfb,0x0d,0xf1,0x2b,
        0x88,0x1d,0xc2,0x6a,0x81,0x9e,0xe6,0x6e
    };
    const uint8_t msg[34] = "Cryptographic Forum Research Group";
    uint8_t tag[16];
    char hex[33];
    fossil_cryptic_auth_poly1305_auth(key, msg, 34, tag);
    for (int i = 0; i < 16; ++i) sprintf(hex + i*2, "%02x", tag[i]);
    hex[32] = 0;
    ASSUME_ITS_EQUAL_CSTR(hex, "a8061dc1305136c6c22b8baf0c0127a9");
}

FOSSIL_TEST_CASE(c_test_poly1305_streaming_equivalence) {
    // Poly1305 one-shot vs streaming should match
    uint8_t key[32] = {0};
    uint8_t msg[64];
    for (int i = 0; i < 32; ++i) key[i] = (uint8_t)i;
    for (int i = 0; i < 64; ++i) msg[i] = (uint8_t)(i + 1);

    uint8_t tag1[16], tag2[16];
    fossil_cryptic_auth_poly1305_auth(key, msg, 64, tag1);

    fossil_cryptic_auth_poly1305_ctx_t ctx;
    fossil_cryptic_auth_poly1305_init(&ctx, key);
    fossil_cryptic_auth_poly1305_update(&ctx, msg, 32);
    fossil_cryptic_auth_poly1305_update(&ctx, msg + 32, 32);
    fossil_cryptic_auth_poly1305_finish(&ctx, tag2);

    ASSUME_ITS_TRUE(fossil_cryptic_auth_consttime_equal(tag1, tag2, 16));
}

FOSSIL_TEST_CASE(c_test_consttime_equal) {
    uint8_t a[8] = {1,2,3,4,5,6,7,8};
    uint8_t b[8] = {1,2,3,4,5,6,7,8};
    uint8_t c[8] = {1,2,3,4,5,6,7,9};
    ASSUME_ITS_TRUE(fossil_cryptic_auth_consttime_equal(a, b, 8));
    ASSUME_ITS_FALSE(fossil_cryptic_auth_consttime_equal(a, c, 8));
}

FOSSIL_TEST_CASE(c_test_chacha20_block_vector) {
    // Test vector from RFC 8439, Section 2.3.2
    const uint8_t key[32] = {
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01
    };
    const uint8_t nonce[12] = {
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x4a,
        0x00,0x00,0x00,0x00
    };
    uint8_t out[64];
    fossil_cryptic_auth_chacha20_block(key, nonce, 1, out);
    // First 4 bytes should be 0x10f1e7e4
    ASSUME_ITS_EQUAL_I32(out[0], 0x10);
    ASSUME_ITS_EQUAL_I32(out[1], 0xf1);
    ASSUME_ITS_EQUAL_I32(out[2], 0xe7);
    ASSUME_ITS_EQUAL_I32(out[3], 0xe4);
}

FOSSIL_TEST_CASE(c_test_chacha20_xor_roundtrip) {
    uint8_t key[32] = {0};
    uint8_t nonce[12] = {0};
    uint8_t msg[128], ct[128], pt[128];
    for (int i = 0; i < 32; ++i) key[i] = (uint8_t)i;
    for (int i = 0; i < 12; ++i) nonce[i] = (uint8_t)(i + 1);
    for (int i = 0; i < 128; ++i) msg[i] = (uint8_t)(i ^ 0xAA);

    fossil_cryptic_auth_chacha20_xor(key, nonce, 1, msg, ct, 128);
    fossil_cryptic_auth_chacha20_xor(key, nonce, 1, ct, pt, 128);

    ASSUME_ITS_TRUE(fossil_cryptic_auth_consttime_equal(msg, pt, 128));
}

FOSSIL_TEST_CASE(c_test_chacha20_poly1305_aead_encrypt_decrypt) {
    // Simple AEAD roundtrip
    uint8_t key[32] = {0};
    uint8_t nonce[12] = {0};
    uint8_t aad[8] = {1,2,3,4,5,6,7,8};
    uint8_t pt[32], ct[32], dec[32], tag[16];
    for (int i = 0; i < 32; ++i) pt[i] = (uint8_t)i;

    fossil_cryptic_auth_chacha20_poly1305_encrypt(key, nonce, aad, 8, pt, 32, ct, tag);
    int ok = fossil_cryptic_auth_chacha20_poly1305_decrypt(key, nonce, aad, 8, ct, 32, dec, tag);

    ASSUME_ITS_TRUE(ok);
    ASSUME_ITS_TRUE(fossil_cryptic_auth_consttime_equal(pt, dec, 32));
}

FOSSIL_TEST_CASE(c_test_chacha20_poly1305_aead_tag_fail) {
    // Tag mismatch should fail
    uint8_t key[32] = {0};
    uint8_t nonce[12] = {0};
    uint8_t aad[8] = {1,2,3,4,5,6,7,8};
    uint8_t pt[16] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
    uint8_t ct[16], tag[16];
    fossil_cryptic_auth_chacha20_poly1305_encrypt(key, nonce, aad, 8, pt, 16, ct, tag);
    tag[0] ^= 0xFF; // Corrupt tag
    uint8_t dec[16];
    int ok = fossil_cryptic_auth_chacha20_poly1305_decrypt(key, nonce, aad, 8, ct, 16, dec, tag);
    ASSUME_ITS_FALSE(ok);
}

// * * * * * * * * * * * * * * * * * * * * * * * *
// * Fossil Logic Test Pool
// * * * * * * * * * * * * * * * * * * * * * * * *
FOSSIL_TEST_GROUP(c_auth_tests) {
    FOSSIL_TEST_ADD(c_auth_fixture, c_test_hmac_sha256_vectors);
    FOSSIL_TEST_ADD(c_auth_fixture, c_test_pbkdf2_sha256_vector);
    FOSSIL_TEST_ADD(c_auth_fixture, c_test_poly1305_oneshot_vector);
    FOSSIL_TEST_ADD(c_auth_fixture, c_test_poly1305_streaming_equivalence);
    FOSSIL_TEST_ADD(c_auth_fixture, c_test_consttime_equal);
    FOSSIL_TEST_ADD(c_auth_fixture, c_test_chacha20_block_vector);
    FOSSIL_TEST_ADD(c_auth_fixture, c_test_chacha20_xor_roundtrip);
    FOSSIL_TEST_ADD(c_auth_fixture, c_test_chacha20_poly1305_aead_encrypt_decrypt);
    FOSSIL_TEST_ADD(c_auth_fixture, c_test_chacha20_poly1305_aead_tag_fail);

    FOSSIL_TEST_REGISTER(c_auth_fixture);
} // end of tests
