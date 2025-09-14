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

FOSSIL_TEST_SUITE(cpp_enc_fixture);

FOSSIL_SETUP(cpp_enc_fixture) {
    // Setup the test fixture
}

FOSSIL_TEARDOWN(cpp_enc_fixture) {
    // Teardown the test fixture
}

// * * * * * * * * * * * * * * * * * * * * * * * *
// * Fossil Logic Test Cases
// * * * * * * * * * * * * * * * * * * * * * * * *
// The test cases below are provided as samples, inspired
// by the Meson build system's approach of using test cases
// as samples for library usage.
// * * * * * * * * * * * * * * * * * * * * * * * *

FOSSIL_TEST_CASE(cpp_encryptor_secure_zero) {
    std::array<uint8_t, 16> buf;
    buf.fill(0xBB);
    fossil::cryptic::Encryptor::secure_zero(buf.data(), buf.size());
    for (size_t i = 0; i < buf.size(); ++i) {
        ASSUME_ITS_EQUAL_I32(buf[i], 0);
    }
}

FOSSIL_TEST_CASE(cpp_encryptor_chacha20_ctr_xor_roundtrip) {
    std::array<uint8_t, 32> key = {};
    std::array<uint8_t, 12> nonce = {};
    std::array<uint8_t, 32> in, out, ref;
    for (size_t i = 0; i < in.size(); ++i) in[i] = (uint8_t)(i + 10);
    fossil::cryptic::Encryptor::chacha20_ctr_xor(key, nonce, 0, in.data(), out.data(), in.size());
    fossil::cryptic::Encryptor::chacha20_ctr_xor(key, nonce, 0, out.data(), ref.data(), out.size());
    for (size_t i = 0; i < in.size(); ++i) {
        ASSUME_ITS_EQUAL_I32(ref[i], in[i]);
    }
}

FOSSIL_TEST_CASE(cpp_encryptor_chacha20_poly1305_encrypt_decrypt) {
    std::array<uint8_t, 32> key = {1,2,3,4};
    std::array<uint8_t, 12> nonce = {5,6,7,8};
    uint8_t aad[8] = {9,10,11,12,13,14,15,16};
    std::array<uint8_t, 32> pt, ct, dec;
    std::array<uint8_t, 16> tag;
    for (size_t i = 0; i < pt.size(); ++i) pt[i] = (uint8_t)(i+2);
    fossil::cryptic::Encryptor::chacha20_poly1305_encrypt(key, nonce, aad, sizeof(aad), pt.data(), pt.size(), ct.data(), tag);
    bool ok = fossil::cryptic::Encryptor::chacha20_poly1305_decrypt(key, nonce, aad, sizeof(aad), ct.data(), ct.size(), dec.data(), tag);
    ASSUME_ITS_EQUAL_I32(ok, 1);
    for (size_t i = 0; i < pt.size(); ++i) {
        ASSUME_ITS_EQUAL_I32(dec[i], pt[i]);
    }
    // Tamper tag
    tag[0] ^= 0xFF;
    ok = fossil::cryptic::Encryptor::chacha20_poly1305_decrypt(key, nonce, aad, sizeof(aad), ct.data(), ct.size(), dec.data(), tag);
    ASSUME_ITS_EQUAL_I32(ok, 0);
}

FOSSIL_TEST_CASE(cpp_encryptor_chacha20_poly1305_empty_aad) {
    std::array<uint8_t, 32> key = {};
    std::array<uint8_t, 12> nonce = {};
    std::array<uint8_t, 8> pt = {1,2,3,4,5,6,7,8}, ct, dec;
    std::array<uint8_t, 16> tag;
    fossil::cryptic::Encryptor::chacha20_poly1305_encrypt(key, nonce, nullptr, 0, pt.data(), pt.size(), ct.data(), tag);
    bool ok = fossil::cryptic::Encryptor::chacha20_poly1305_decrypt(key, nonce, nullptr, 0, ct.data(), ct.size(), dec.data(), tag);
    ASSUME_ITS_EQUAL_I32(ok, 1);
    for (size_t i = 0; i < pt.size(); ++i) {
        ASSUME_ITS_EQUAL_I32(dec[i], pt[i]);
    }
}

FOSSIL_TEST_CASE(cpp_encryptor_aes128_ctr_encrypt_then_mac_and_verify_then_decrypt) {
    std::array<uint8_t, 16> key = {};
    std::array<uint8_t, 16> iv = {};
    uint8_t aad[8] = {1,2,3,4,5,6,7,8};
    std::array<uint8_t, 32> pt, ct, dec;
    std::array<uint8_t, 32> mac;
    for (size_t i = 0; i < pt.size(); ++i) pt[i] = (uint8_t)(i+3);
    fossil::cryptic::Encryptor::aes128_ctr_encrypt_then_mac_hmac_sha256(key, iv, aad, sizeof(aad), pt.data(), pt.size(), ct.data(), mac);
    bool ok = fossil::cryptic::Encryptor::aes128_ctr_verify_then_decrypt_hmac_sha256(key, iv, aad, sizeof(aad), ct.data(), ct.size(), dec.data(), mac);
    ASSUME_ITS_EQUAL_I32(ok, 1);
    for (size_t i = 0; i < pt.size(); ++i) {
        ASSUME_ITS_EQUAL_I32(dec[i], pt[i]);
    }
    // Tamper MAC
    mac[0] ^= 0xFF;
    ok = fossil::cryptic::Encryptor::aes128_ctr_verify_then_decrypt_hmac_sha256(key, iv, aad, sizeof(aad), ct.data(), ct.size(), dec.data(), mac);
    ASSUME_ITS_EQUAL_I32(ok, 0);
}

FOSSIL_TEST_CASE(cpp_encryptor_aes128_ctr_encrypt_then_mac_empty_aad) {
    std::array<uint8_t, 16> key = {};
    std::array<uint8_t, 16> iv = {};
    std::array<uint8_t, 8> pt = {1,2,3,4,5,6,7,8}, ct, dec;
    std::array<uint8_t, 32> mac;
    fossil::cryptic::Encryptor::aes128_ctr_encrypt_then_mac_hmac_sha256(key, iv, nullptr, 0, pt.data(), pt.size(), ct.data(), mac);
    bool ok = fossil::cryptic::Encryptor::aes128_ctr_verify_then_decrypt_hmac_sha256(key, iv, nullptr, 0, ct.data(), ct.size(), dec.data(), mac);
    ASSUME_ITS_EQUAL_I32(ok, 1);
    for (size_t i = 0; i < pt.size(); ++i) {
        ASSUME_ITS_EQUAL_I32(dec[i], pt[i]);
    }
}

// * * * * * * * * * * * * * * * * * * * * * * * *
// * Fossil Logic Test Pool
// * * * * * * * * * * * * * * * * * * * * * * * *
FOSSIL_TEST_GROUP(cpp_enc_tests) {
    FOSSIL_TEST_ADD(cpp_enc_fixture, cpp_encryptor_secure_zero);
    FOSSIL_TEST_ADD(cpp_enc_fixture, cpp_encryptor_chacha20_ctr_xor_roundtrip);
    FOSSIL_TEST_ADD(cpp_enc_fixture, cpp_encryptor_chacha20_poly1305_encrypt_decrypt);
    FOSSIL_TEST_ADD(cpp_enc_fixture, cpp_encryptor_chacha20_poly1305_empty_aad);
    FOSSIL_TEST_ADD(cpp_enc_fixture, cpp_encryptor_aes128_ctr_encrypt_then_mac_and_verify_then_decrypt);
    FOSSIL_TEST_ADD(cpp_enc_fixture, cpp_encryptor_aes128_ctr_encrypt_then_mac_empty_aad);

    FOSSIL_TEST_REGISTER(cpp_enc_fixture);
} // end of tests
