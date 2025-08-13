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

FOSSIL_TEST_SUITE(c_enc_fixture);

FOSSIL_SETUP(c_enc_fixture) {
    // Setup the test fixture
}

FOSSIL_TEARDOWN(c_enc_fixture) {
    // Teardown the test fixture
}

// * * * * * * * * * * * * * * * * * * * * * * * *
// * Fossil Logic Test Cases
// * * * * * * * * * * * * * * * * * * * * * * * *
// The test cases below are provided as samples, inspired
// by the Meson build system's approach of using test cases
// as samples for library usage.
// * * * * * * * * * * * * * * * * * * * * * * * *

FOSSIL_TEST_CASE(c_test_secure_zero) {
    uint8_t buf[16];
    memset(buf, 0xAA, sizeof(buf));
    fossil_cryptic_enc_secure_zero(buf, sizeof(buf));
    for (size_t i = 0; i < sizeof(buf); ++i) {
        ASSUME_ITS_EQUAL_I32(buf[i], 0);
    }
}

FOSSIL_TEST_CASE(c_test_chacha20_ctr_xor) {
    uint8_t key[32] = {0};
    uint8_t nonce[12] = {0};
    uint8_t in[32], out[32], ref[32];
    for (int i = 0; i < 32; ++i) in[i] = (uint8_t)i;
    // Encrypt
    fossil_cryptic_enc_chacha20_ctr_xor(key, nonce, 0, in, out, 32);
    // Decrypt (XOR again with same keystream)
    fossil_cryptic_enc_chacha20_ctr_xor(key, nonce, 0, out, ref, 32);
    for (int i = 0; i < 32; ++i) {
        ASSUME_ITS_EQUAL_I32(ref[i], in[i]);
    }
}

FOSSIL_TEST_CASE(c_test_chacha20_poly1305_encrypt_decrypt) {
    uint8_t key[32] = {1,2,3,4};
    uint8_t nonce[12] = {5,6,7,8};
    uint8_t aad[8] = {9,10,11,12,13,14,15,16};
    uint8_t pt[32], ct[32], tag[16], dec[32];
    for (int i = 0; i < 32; ++i) pt[i] = (uint8_t)(i+1);
    fossil_cryptic_enc_chacha20_poly1305_encrypt(key, nonce, aad, sizeof(aad), pt, sizeof(pt), ct, tag);
    int ok = fossil_cryptic_enc_chacha20_poly1305_decrypt(key, nonce, aad, sizeof(aad), ct, sizeof(ct), dec, tag);
    ASSUME_ITS_EQUAL_I32(ok, 1);
    for (int i = 0; i < 32; ++i) {
        ASSUME_ITS_EQUAL_I32(dec[i], pt[i]);
    }
    // Tamper tag
    tag[0] ^= 0xFF;
    ok = fossil_cryptic_enc_chacha20_poly1305_decrypt(key, nonce, aad, sizeof(aad), ct, sizeof(ct), dec, tag);
    ASSUME_ITS_EQUAL_I32(ok, 0);
}

FOSSIL_TEST_CASE(c_test_aes128_ctr_encrypt_then_mac_and_verify_then_decrypt) {
    uint8_t key[16] = {0};
    uint8_t iv[16] = {0};
    uint8_t aad[8] = {1,2,3,4,5,6,7,8};
    uint8_t pt[32], ct[32], mac[32], dec[32];
    for (int i = 0; i < 32; ++i) pt[i] = (uint8_t)(i+1);
    fossil_cryptic_enc_aes128_ctr_encrypt_then_mac_hmac_sha256(key, iv, aad, sizeof(aad), pt, sizeof(pt), ct, mac);
    int ok = fossil_cryptic_enc_aes128_ctr_verify_then_decrypt_hmac_sha256(key, iv, aad, sizeof(aad), ct, sizeof(ct), dec, mac);
    ASSUME_ITS_EQUAL_I32(ok, 1);
    for (int i = 0; i < 32; ++i) {
        ASSUME_ITS_EQUAL_I32(dec[i], pt[i]);
    }
    // Tamper MAC
    mac[0] ^= 0xFF;
    ok = fossil_cryptic_enc_aes128_ctr_verify_then_decrypt_hmac_sha256(key, iv, aad, sizeof(aad), ct, sizeof(ct), dec, mac);
    ASSUME_ITS_EQUAL_I32(ok, 0);
}

FOSSIL_TEST_CASE(c_test_aes128_ctr_encrypt_then_mac_empty_aad) {
    uint8_t key[16] = {0};
    uint8_t iv[16] = {0};
    uint8_t pt[8] = {1,2,3,4,5,6,7,8};
    uint8_t ct[8], mac[32], dec[8];
    fossil_cryptic_enc_aes128_ctr_encrypt_then_mac_hmac_sha256(key, iv, NULL, 0, pt, sizeof(pt), ct, mac);
    int ok = fossil_cryptic_enc_aes128_ctr_verify_then_decrypt_hmac_sha256(key, iv, NULL, 0, ct, sizeof(ct), dec, mac);
    ASSUME_ITS_EQUAL_I32(ok, 1);
    for (int i = 0; i < 8; ++i) {
        ASSUME_ITS_EQUAL_I32(dec[i], pt[i]);
    }
}

// * * * * * * * * * * * * * * * * * * * * * * * *
// * Fossil Logic Test Pool
// * * * * * * * * * * * * * * * * * * * * * * * *
FOSSIL_TEST_GROUP(c_enc_tests) {
    FOSSIL_TEST_ADD(c_enc_fixture, c_test_secure_zero);
    FOSSIL_TEST_ADD(c_enc_fixture, c_test_chacha20_ctr_xor);
    FOSSIL_TEST_ADD(c_enc_fixture, c_test_chacha20_poly1305_encrypt_decrypt);
    FOSSIL_TEST_ADD(c_enc_fixture, c_test_aes128_ctr_encrypt_then_mac_and_verify_then_decrypt);
    FOSSIL_TEST_ADD(c_enc_fixture, c_test_aes128_ctr_encrypt_then_mac_empty_aad);

    FOSSIL_TEST_REGISTER(c_enc_fixture);
} // end of tests
