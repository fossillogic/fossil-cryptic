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
#include "fossil/cryptic/auth.h"
#include "fossil/cryptic/hash.h"
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

// Stub type and function definitions to resolve linker errors
typedef struct {
    uint8_t data[256];
} fossil_cryptic_auth_poly1305_ctx_t;

/* Minimal HMAC-SHA256 implementation using fossil_cryptic_hash_sha256 */
void fossil_cryptic_auth_hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len, uint8_t *out)
{
    uint8_t k_ipad[64] = {0}, k_opad[64] = {0}, tk[32], inner_hash[32];
    size_t i;

    if (key_len > 64) {
        fossil_cryptic_hash_sha256(key, key_len, tk);
        key = tk;
        key_len = 32;
    }

    memcpy(k_ipad, key, key_len);
    memcpy(k_opad, key, key_len);

    for (i = 0; i < 64; ++i) {
        k_ipad[i] ^= 0x36;
        k_opad[i] ^= 0x5c;
    }

    uint8_t inner_data[64 + data_len];
    memcpy(inner_data, k_ipad, 64);
    memcpy(inner_data + 64, data, data_len);
    fossil_cryptic_hash_sha256(inner_data, 64 + data_len, inner_hash);

    uint8_t outer_data[64 + 32];
    memcpy(outer_data, k_opad, 64);
    memcpy(outer_data + 64, inner_hash, 32);
    fossil_cryptic_hash_sha256(outer_data, 64 + 32, out);
}

/* Minimal PBKDF2-HMAC-SHA256 implementation */
void fossil_cryptic_auth_pbkdf2_sha256(const char *password, size_t pass_len, const uint8_t *salt, size_t salt_len, int iterations, uint8_t *out, size_t out_len)
{
    uint32_t i, j, k, blocks = (out_len + 31) / 32;
    uint8_t U[32], T[32], block_salt[salt_len + 4];

    for (i = 1; i <= blocks; ++i) {
        memcpy(block_salt, salt, salt_len);
        block_salt[salt_len + 0] = (i >> 24) & 0xff;
        block_salt[salt_len + 1] = (i >> 16) & 0xff;
        block_salt[salt_len + 2] = (i >> 8) & 0xff;
        block_salt[salt_len + 3] = (i) & 0xff;

        fossil_cryptic_auth_hmac_sha256((const uint8_t *)password, pass_len, block_salt, salt_len + 4, U);
        memcpy(T, U, 32);

        for (j = 1; j < (uint32_t)iterations; ++j) {
            fossil_cryptic_auth_hmac_sha256((const uint8_t *)password, pass_len, U, 32, U);
            for (k = 0; k < 32; ++k)
                T[k] ^= U[k];
        }

        size_t offset = (i - 1) * 32;
        size_t to_copy = (out_len - offset > 32) ? 32 : (out_len - offset);
        memcpy(out + offset, T, to_copy);
    }
}

/* Poly1305 stub (not implemented, just zeroes out tag) */
void fossil_cryptic_auth_poly1305_auth(const uint8_t key[32], const uint8_t *msg, size_t msg_len, uint8_t tag[16])
{
    memset(tag, 0, 16);
}

/* Poly1305 context stub functions */
void fossil_cryptic_auth_poly1305_init(fossil_cryptic_auth_poly1305_ctx_t* ctx, const uint8_t key[32])
{
    memset(ctx, 0, sizeof(*ctx));
}

void fossil_cryptic_auth_poly1305_update(fossil_cryptic_auth_poly1305_ctx_t* ctx, const uint8_t* msg, size_t msg_len)
{
    (void)ctx; (void)msg; (void)msg_len;
}

void fossil_cryptic_auth_poly1305_finish(fossil_cryptic_auth_poly1305_ctx_t* ctx, uint8_t tag[16])
{
    memset(tag, 0, 16);
}

/* Constant-time comparison */
int fossil_cryptic_auth_consttime_equal(const uint8_t *a, const uint8_t *b, size_t len)
{
    uint8_t res = 0;
    for (size_t i = 0; i < len; ++i)
        res |= a[i] ^ b[i];
    return res == 0;
}

/* ChaCha20 block stub (not implemented) */
void fossil_cryptic_auth_chacha20_block(const uint8_t key[32], const uint8_t nonce[12], uint32_t counter, uint8_t *out)
{
    memset(out, 0, 64);
}

/* ChaCha20 XOR stub (not implemented) */
void fossil_cryptic_auth_chacha20_xor(const uint8_t key[32], const uint8_t nonce[12], uint32_t counter, const uint8_t *in, uint8_t *out, size_t len)
{
    memset(out, 0, len);
}

/* ChaCha20-Poly1305 AEAD stubs (not implemented) */
void fossil_cryptic_auth_chacha20_poly1305_encrypt(const uint8_t key[32], const uint8_t nonce[12], const uint8_t *aad, size_t aad_len, const uint8_t *plaintext, size_t pt_len, uint8_t *ciphertext, uint8_t tag[16])
{
    memset(ciphertext, 0, pt_len);
    memset(tag, 0, 16);
}

int fossil_cryptic_auth_chacha20_poly1305_decrypt(const uint8_t key[32], const uint8_t nonce[12], const uint8_t *aad, size_t aad_len, const uint8_t *ciphertext, size_t ct_len, uint8_t *plaintext, const uint8_t tag[16])
{
    memset(plaintext, 0, ct_len);
    return 0;
}

/* Enhanced fallback RNG (non-crypto, portable, seeded) */
static uint32_t fossil_rand32(void) {
    static uint32_t s = 0;
    if (s == 0) {
        s = (uint32_t)time(NULL) ^ (uint32_t)(uintptr_t)&s;
    }
    s ^= s << 13;
    s ^= s >> 17;
    s ^= s << 5;
    return s;
}

static void fossil_fill_rand_bytes(uint8_t *buf, size_t n) {
    for (size_t i = 0; i < n; ++i)
        buf[i] = (uint8_t)(fossil_rand32() & 0xFF);
}

/* ------------------------------------------------------------------------
 * Salt and Challenge
 * ------------------------------------------------------------------------ */

int fossil_cryptic_auth_generate_salt(char *out, size_t outlen) {
    if (!out || outlen < 16) return -1;
    uint8_t tmp[16];
    fossil_fill_rand_bytes(tmp, sizeof(tmp));
    if (fossil_cryptic_hash_to_str(tmp, sizeof(tmp), "fnv1a64", "u64", "base64", out, outlen) != 0)
        return -2;
    return 0;
}

int fossil_cryptic_auth_generate_challenge(char *out, size_t outlen) {
    if (!out || outlen < 24) return -1;
    char salt[32];
    if (fossil_cryptic_auth_generate_salt(salt, sizeof(salt)) != 0)
        return -2;
    char timebuf[32];
    snprintf(timebuf, sizeof(timebuf), "%lu", (unsigned long)time(NULL));

    char combined[128];
    snprintf(combined, sizeof(combined), "%s:%s", timebuf, salt);

    if (fossil_cryptic_hash_to_str(combined, strlen(combined),
                                   "murmur3", "auto", "base64",
                                   out, outlen) != 0)
        return -3;
    return 0;
}

/* ------------------------------------------------------------------------
 * Password Hashing
 * ------------------------------------------------------------------------ */

int fossil_cryptic_auth_hash_password(const char *password,
                                      const char *salt,
                                      const char *alg,
                                      const char *bit_pref,
                                      const char *base_pref,
                                      char *out, size_t outlen)
{
    if (!password || !salt || !out) return -1;
    char combined[512];
    snprintf(combined, sizeof(combined), "%s:%s", salt, password);
    return fossil_cryptic_hash_to_str(combined, strlen(combined),
                                      alg, bit_pref, base_pref,
                                      out, outlen);
}

int fossil_cryptic_auth_verify_password(const char *password,
                                        const char *salt,
                                        const char *expected,
                                        const char *alg,
                                        const char *bit_pref,
                                        const char *base_pref)
{
    if (!password || !salt || !expected) return -1;
    char computed[128];
    if (fossil_cryptic_auth_hash_password(password, salt, alg, bit_pref, base_pref,
                                          computed, sizeof(computed)) != 0)
        return -2;
    return strcmp(expected, computed) == 0 ? 1 : 0;
}

/* ------------------------------------------------------------------------
 * Token Signing
 * ------------------------------------------------------------------------ */

int fossil_cryptic_auth_sign_token(const char *key,
                                   const char *payload,
                                   const char *alg,
                                   const char *bit_pref,
                                   const char *base_pref,
                                   char *out, size_t outlen)
{
    if (!key || !payload || !out) return -1;
    char combined[512];
    snprintf(combined, sizeof(combined), "%s:%s", key, payload);
    return fossil_cryptic_hash_to_str(combined, strlen(combined),
                                      alg, bit_pref, base_pref,
                                      out, outlen);
}

int fossil_cryptic_auth_verify_token(const char *key,
                                     const char *payload,
                                     const char *expected,
                                     const char *alg,
                                     const char *bit_pref,
                                     const char *base_pref)
{
    if (!key || !payload || !expected) return -1;
    char computed[128];
    if (fossil_cryptic_auth_sign_token(key, payload, alg, bit_pref, base_pref,
                                       computed, sizeof(computed)) != 0)
        return -2;
    return strcmp(expected, computed) == 0 ? 1 : 0;
}
