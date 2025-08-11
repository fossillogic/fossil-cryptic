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
#include "fossil/cryptic/auth.h"
#include "fossil/cryptic/hash.h"
#include <string.h>

/* =======================
 *  HMAC-SHA256
 * ======================= */
void fossil_cryptic_auth_hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len, uint8_t out[32]) {
    uint8_t k_ipad[64], k_opad[64], tk[32];
    size_t i;

    /* Step 1: If key is longer than block size, shorten with SHA-256 */
    if (key_len > 64) {
        fossil_cryptic_hash_sha256(key, key_len, tk);
        key = tk;
        key_len = 32;
    }

    /* Step 2: Fill pads */
    memset(k_ipad, 0x36, 64);
    memset(k_opad, 0x5c, 64);

    for (i = 0; i < key_len; i++) {
        k_ipad[i] ^= key[i];
        k_opad[i] ^= key[i];
    }

    /* Step 3: Inner SHA-256 */
    fossil_cryptic_hash_sha256_ctx_t ctx;
    uint8_t inner_hash[32];

    fossil_cryptic_hash_sha256_init(&ctx);
    fossil_cryptic_hash_sha256_update(&ctx, k_ipad, 64);
    fossil_cryptic_hash_sha256_update(&ctx, data, data_len);
    fossil_cryptic_hash_sha256_final(&ctx, inner_hash);

    /* Step 4: Outer SHA-256 */
    fossil_cryptic_hash_sha256_init(&ctx);
    fossil_cryptic_hash_sha256_update(&ctx, k_opad, 64);
    fossil_cryptic_hash_sha256_update(&ctx, inner_hash, 32);
    fossil_cryptic_hash_sha256_final(&ctx, out);
}

/* =======================
 *  PBKDF2-HMAC-SHA256
 * ======================= */
void fossil_cryptic_auth_pbkdf2_sha256(const uint8_t *password, size_t pass_len, const uint8_t *salt, size_t salt_len, uint32_t iterations, uint8_t *out, size_t out_len) {
    uint32_t block_count = (out_len + 31) / 32;
    uint8_t U[32], T[32];
    uint8_t salt_block[1024]; /* Big enough for most salts */
    size_t i, j, k;

    for (i = 1; i <= block_count; i++) {
        /* Prepare salt || INT_32_BE(i) */
        memcpy(salt_block, salt, salt_len);
        salt_block[salt_len + 0] = (i >> 24) & 0xff;
        salt_block[salt_len + 1] = (i >> 16) & 0xff;
        salt_block[salt_len + 2] = (i >> 8) & 0xff;
        salt_block[salt_len + 3] = (i) & 0xff;

        /* U1 = HMAC(password, salt||block_index) */
        fossil_cryptic_auth_hmac_sha256(password, pass_len, salt_block, salt_len + 4, U);
        memcpy(T, U, 32);

        /* U2..U_iter */
        for (j = 1; j < iterations; j++) {
            fossil_cryptic_auth_hmac_sha256(password, pass_len, U, 32, U);
            for (k = 0; k < 32; k++) {
                T[k] ^= U[k];
            }
        }

        /* Copy T into output buffer */
        size_t offset = (i - 1) * 32;
        size_t to_copy = (out_len - offset) < 32 ? (out_len - offset) : 32;
        memcpy(out + offset, T, to_copy);
    }
}
