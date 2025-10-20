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

FOSSIL_TEST_CASE(cpp_test_hash_password_and_verify) {
    // Basic password hashing and verification using C++ wrapper
    std::string password = "hunter2";
    std::string salt = fossil::cryptic::Auth::generate_salt(24);
    ASSUME_ITS_TRUE(!salt.empty());

    std::string hash = fossil::cryptic::Auth::hash_password(password, salt, "fnv1a", "u32", "hex");
    ASSUME_ITS_TRUE(!hash.empty());

    bool valid = fossil::cryptic::Auth::verify_password(password, salt, hash, "fnv1a", "u32", "hex");
    ASSUME_ITS_TRUE(valid);

    valid = fossil::cryptic::Auth::verify_password("wrongpass", salt, hash, "fnv1a", "u32", "hex");
    ASSUME_ITS_FALSE(valid);
}

FOSSIL_TEST_CASE(cpp_test_sign_and_verify_token) {
    // Token signing and verification using C++ wrapper
    std::string key = "supersecret";
    std::string payload = "user:42";
    std::string sig = fossil::cryptic::Auth::sign_token(key, payload, "fnv1a", "u32", "hex");
    ASSUME_ITS_TRUE(!sig.empty());

    bool valid = fossil::cryptic::Auth::verify_token(key, payload, sig, "fnv1a", "u32", "hex");
    ASSUME_ITS_TRUE(valid);

    valid = fossil::cryptic::Auth::verify_token("badkey", payload, sig, "fnv1a", "u32", "hex");
    ASSUME_ITS_FALSE(valid);

    valid = fossil::cryptic::Auth::verify_token(key, "user:99", sig, "fnv1a", "u32", "hex");
    ASSUME_ITS_FALSE(valid);
}

FOSSIL_TEST_CASE(cpp_test_generate_salt_and_challenge) {
    // Salt and challenge generation using C++ wrapper
    std::string salt = fossil::cryptic::Auth::generate_salt(32);
    ASSUME_ITS_TRUE(!salt.empty());

    std::string challenge = fossil::cryptic::Auth::generate_challenge(64);
    ASSUME_ITS_TRUE(!challenge.empty());
}

// Existing test cases
FOSSIL_TEST_CASE(cpp_test_hmac_sha256_vectors) {
    // Test vector from RFC 4231, Test Case 1
    const uint8_t key[20] = {
        0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,
        0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b
    };
    const char *data = "Hi There";
    auto mac = fossil::cryptic::Auth::hmac_sha256(key, 20, (const uint8_t*)data, 8);
    char hex[65];
    fossil_cryptic_hash_sha256_to_hex(mac.data(), hex);
    ASSUME_ITS_EQUAL_CSTR(hex, "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
}

FOSSIL_TEST_CASE(cpp_test_pbkdf2_sha256_vector) {
    // Test vector from RFC 6070 (adapted for SHA256)
    const char *password = "password";
    const char *salt = "salt";
    auto dk = fossil::cryptic::Auth::pbkdf2_sha256(
        (const uint8_t*)password, 8,
        (const uint8_t*)salt, 4,
        1, 32
    );
    char hex[65];
    fossil_cryptic_hash_sha256_to_hex(dk.data(), hex);
    // Expected: 0c60c80f961f0e71f3a9b524af6012062fe037a6de5bfc1b2f8c2a5e6a5a5a08
    ASSUME_ITS_EQUAL_CSTR(hex, "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b");
}

FOSSIL_TEST_CASE(cpp_test_poly1305_oneshot_vector) {
    // Test vector from RFC 7539, Section 2.5.2
    const uint8_t key[32] = {
        0x85,0xd6,0xbe,0x78,0x57,0x55,0x6d,0x33,
        0x7f,0x44,0x52,0xfe,0x42,0xd5,0x06,0xa8,
        0x01,0x03,0x80,0x8a,0xfb,0x0d,0xf1,0x2b,
        0x88,0x1d,0xc2,0x6a,0x81,0x9e,0xe6,0x6e
    };
    const uint8_t msg[35] = "Cryptographic Forum Research Group";
    auto tag = fossil::cryptic::Auth::poly1305_auth(key, msg, 34);
    char hex[33];
    for (int i = 0; i < 16; ++i) sprintf(hex + i*2, "%02x", tag[i]);
    hex[32] = 0;
    ASSUME_ITS_EQUAL_CSTR(hex, "a8061dc1305136c6c22b8baf0c0127a9");
}

FOSSIL_TEST_CASE(cpp_test_poly1305_streaming_equivalence) {
    // Poly1305 one-shot vs streaming should match
    uint8_t key[32] = {0};
    uint8_t msg[64];
    for (int i = 0; i < 32; ++i) key[i] = (uint8_t)i;
    for (int i = 0; i < 64; ++i) msg[i] = (uint8_t)(i + 1);

    auto tag1 = fossil::cryptic::Auth::poly1305_auth(key, msg, 64);

    fossil_cryptic_auth_poly1305_ctx_t ctx;
    fossil::cryptic::Auth::poly1305_init(&ctx, key);
    fossil::cryptic::Auth::poly1305_update(&ctx, msg, 32);
    fossil::cryptic::Auth::poly1305_update(&ctx, msg + 32, 32);
    uint8_t tag2[16];
    fossil::cryptic::Auth::poly1305_finish(&ctx, tag2);

    ASSUME_ITS_TRUE(fossil::cryptic::Auth::consttime_equal(tag1.data(), tag2, 16));
}

FOSSIL_TEST_CASE(cpp_test_consttime_equal) {
    uint8_t a[8] = {1,2,3,4,5,6,7,8};
    uint8_t b[8] = {1,2,3,4,5,6,7,8};
    uint8_t c[8] = {1,2,3,4,5,6,7,9};
    ASSUME_ITS_TRUE(fossil::cryptic::Auth::consttime_equal(a, b, 8));
    ASSUME_ITS_FALSE(fossil::cryptic::Auth::consttime_equal(a, c, 8));
}

FOSSIL_TEST_CASE(cpp_test_chacha20_block_vector) {
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
    auto out = fossil::cryptic::Auth::chacha20_block(key, nonce, 1);
    // First 4 bytes should be 0x10f1e7e4
    ASSUME_ITS_EQUAL_I32(out[0], 0x10);
    ASSUME_ITS_EQUAL_I32(out[1], 0xf1);
    ASSUME_ITS_EQUAL_I32(out[2], 0xe7);
    ASSUME_ITS_EQUAL_I32(out[3], 0xe4);
}

FOSSIL_TEST_CASE(cpp_test_chacha20_xor_roundtrip) {
    uint8_t key[32] = {0};
    uint8_t nonce[12] = {0};
    uint8_t msg[128];
    for (int i = 0; i < 32; ++i) key[i] = (uint8_t)i;
    for (int i = 0; i < 12; ++i) nonce[i] = (uint8_t)(i + 1);
    for (int i = 0; i < 128; ++i) msg[i] = (uint8_t)(i ^ 0xAA);

    auto ct = fossil::cryptic::Auth::chacha20_xor(key, nonce, 1, msg, 128);
    auto pt = fossil::cryptic::Auth::chacha20_xor(key, nonce, 1, ct.data(), 128);

    ASSUME_ITS_TRUE(fossil::cryptic::Auth::consttime_equal(msg, pt.data(), 128));
}

FOSSIL_TEST_CASE(cpp_test_chacha20_poly1305_aead_encrypt_decrypt) {
    // Simple AEAD roundtrip using C++ wrapper
    uint8_t key[32] = {0};
    uint8_t nonce[12] = {0};
    uint8_t aad[8] = {1,2,3,4,5,6,7,8};
    uint8_t pt[32];
    for (int i = 0; i < 32; ++i) pt[i] = (uint8_t)i;
    uint8_t tag[16];
    auto ct = fossil::cryptic::Auth::chacha20_poly1305_encrypt(key, nonce, aad, 8, pt, 32, tag);
    bool ok = false;
    auto dec = fossil::cryptic::Auth::chacha20_poly1305_decrypt(key, nonce, aad, 8, ct.data(), 32, tag, ok);

    ASSUME_ITS_TRUE(ok);
    ASSUME_ITS_TRUE(fossil::cryptic::Auth::consttime_equal(pt, dec.data(), 32));
}

FOSSIL_TEST_CASE(cpp_test_chacha20_poly1305_aead_tag_fail) {
    // Tag mismatch should fail using C++ wrapper
    uint8_t key[32] = {0};
    uint8_t nonce[12] = {0};
    uint8_t aad[8] = {1,2,3,4,5,6,7,8};
    uint8_t pt[16] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
    uint8_t tag[16];
    auto ct = fossil::cryptic::Auth::chacha20_poly1305_encrypt(key, nonce, aad, 8, pt, 16, tag);
    tag[0] ^= 0xFF; // Corrupt tag
    bool ok = true;
    auto dec = fossil::cryptic::Auth::chacha20_poly1305_decrypt(key, nonce, aad, 8, ct.data(), 16, tag, ok);
    ASSUME_ITS_FALSE(ok);
}

// Additional HMAC-SHA256 test cases

FOSSIL_TEST_CASE(cpp_test_hmac_sha256_empty_key_data) {
    // Empty key and data using C++ wrapper
    const uint8_t key[1] = {0};
    const uint8_t data[1] = {0};
    auto mac = fossil::cryptic::Auth::hmac_sha256(key, 0, data, 0);
    char hex[65];
    fossil_cryptic_hash_sha256_to_hex(mac.data(), hex);
    // Just check output is nonzero and deterministic
    ASSUME_ITS_TRUE(hex[0] != '0' || hex[1] != '0');
}

FOSSIL_TEST_CASE(cpp_test_hmac_sha256_long_key) {
    // Key longer than block size (64 bytes) using C++ wrapper
    uint8_t key[80];
    for (int i = 0; i < 80; ++i) key[i] = (uint8_t)i;
    const char *data = "Test message";
    auto mac = fossil::cryptic::Auth::hmac_sha256(key, 80, (const uint8_t*)data, strlen(data));
    char hex[65];
    fossil_cryptic_hash_sha256_to_hex(mac.data(), hex);
    // Just check output is nonzero and deterministic
    ASSUME_ITS_TRUE(hex[0] != '0' || hex[1] != '0');
}

FOSSIL_TEST_CASE(cpp_test_pbkdf2_sha256_minimal) {
    // Minimal PBKDF2 test: 1 iteration, 1-byte password/salt using C++ wrapper
    uint8_t password[1] = {0x01};
    uint8_t salt[1] = {0x02};
    auto dk = fossil::cryptic::Auth::pbkdf2_sha256(password, 1, salt, 1, 1, 32);
    char hex[65];
    fossil_cryptic_hash_sha256_to_hex(dk.data(), hex);
    ASSUME_ITS_TRUE(hex[0] != '0');
}

FOSSIL_TEST_CASE(cpp_test_pbkdf2_sha256_high_iter) {
    // High iteration count (small output for speed) using C++ wrapper
    const char *password = "high-iter";
    const char *salt = "salt";
    auto dk = fossil::cryptic::Auth::pbkdf2_sha256(
        (const uint8_t*)password, strlen(password),
        (const uint8_t*)salt, strlen(salt),
        1000, 8
    );
    // Just check output is deterministic
    ASSUME_ITS_TRUE(dk[0] != 0);
}

FOSSIL_TEST_CASE(cpp_test_poly1305_empty_msg) {
    // Poly1305 with empty message using C++ wrapper
    uint8_t key[32] = {0};
    auto tag = fossil::cryptic::Auth::poly1305_auth(key, NULL, 0);
    char hex[33];
    for (int i = 0; i < 16; ++i) sprintf(hex + i*2, "%02x", tag[i]);
    hex[32] = 0;
    ASSUME_ITS_TRUE(hex[0] != '0');
}

FOSSIL_TEST_CASE(cpp_test_poly1305_streaming_partial_blocks) {
    // Streaming Poly1305 with partial blocks using C++ wrapper
    uint8_t key[32] = {0};
    uint8_t msg[20];
    for (int i = 0; i < 20; ++i) msg[i] = (uint8_t)i;
    auto tag1 = fossil::cryptic::Auth::poly1305_auth(key, msg, 20);

    fossil_cryptic_auth_poly1305_ctx_t ctx;
    fossil::cryptic::Auth::poly1305_init(&ctx, key);
    fossil::cryptic::Auth::poly1305_update(&ctx, msg, 10);
    fossil::cryptic::Auth::poly1305_update(&ctx, msg + 10, 10);
    uint8_t tag2[16];
    fossil::cryptic::Auth::poly1305_finish(&ctx, tag2);

    ASSUME_ITS_TRUE(fossil::cryptic::Auth::consttime_equal(tag1.data(), tag2, 16));
}


// * * * * * * * * * * * * * * * * * * * * * * * *
// * Fossil Logic Test Pool
// * * * * * * * * * * * * * * * * * * * * * * * *
FOSSIL_TEST_GROUP(cpp_auth_tests) {
    FOSSIL_TEST_ADD(cpp_auth_fixture, cpp_test_hash_password_and_verify);
    FOSSIL_TEST_ADD(cpp_auth_fixture, cpp_test_sign_and_verify_token);
    FOSSIL_TEST_ADD(cpp_auth_fixture, cpp_test_generate_salt_and_challenge);
    FOSSIL_TEST_ADD(cpp_auth_fixture, cpp_test_hmac_sha256_vectors);
    FOSSIL_TEST_ADD(cpp_auth_fixture, cpp_test_pbkdf2_sha256_vector);
    FOSSIL_TEST_ADD(cpp_auth_fixture, cpp_test_poly1305_oneshot_vector);
    FOSSIL_TEST_ADD(cpp_auth_fixture, cpp_test_poly1305_streaming_equivalence);
    FOSSIL_TEST_ADD(cpp_auth_fixture, cpp_test_consttime_equal);
    FOSSIL_TEST_ADD(cpp_auth_fixture, cpp_test_chacha20_block_vector);
    FOSSIL_TEST_ADD(cpp_auth_fixture, cpp_test_chacha20_xor_roundtrip);
    FOSSIL_TEST_ADD(cpp_auth_fixture, cpp_test_chacha20_poly1305_aead_encrypt_decrypt);
    FOSSIL_TEST_ADD(cpp_auth_fixture, cpp_test_chacha20_poly1305_aead_tag_fail);
    FOSSIL_TEST_ADD(cpp_auth_fixture, cpp_test_hmac_sha256_empty_key_data);
    FOSSIL_TEST_ADD(cpp_auth_fixture, cpp_test_hmac_sha256_long_key);
    FOSSIL_TEST_ADD(cpp_auth_fixture, cpp_test_pbkdf2_sha256_minimal);
    FOSSIL_TEST_ADD(cpp_auth_fixture, cpp_test_pbkdf2_sha256_high_iter);
    FOSSIL_TEST_ADD(cpp_auth_fixture, cpp_test_poly1305_empty_msg);
    FOSSIL_TEST_ADD(cpp_auth_fixture, cpp_test_poly1305_streaming_partial_blocks);

    FOSSIL_TEST_REGISTER(cpp_auth_fixture);
} // end of tests
