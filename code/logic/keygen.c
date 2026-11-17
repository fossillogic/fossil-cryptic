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
#include "fossil/cryptic/keygen.h"
#include "fossil/cryptic/auth.h"
#include "fossil/cryptic/hash.h"
#include "fossil/cryptic/util.h"
#include <string.h>
#include <stdlib.h>

/* ---------- HKDF-SHA256 ---------- */

static int hkdf_extract(const uint8_t *salt, size_t salt_len,
                        const uint8_t *ikm, size_t ikm_len,
                        uint8_t prk[32])
{
    static const uint8_t zeros[32] = {0};
    if (!salt || salt_len == 0) {
        salt = zeros;
        salt_len = 32;
    }
    return fossil_cryptic_auth_hmac_sha256(salt, salt_len, ikm, ikm_len, prk);
}

static int hkdf_expand(const uint8_t prk[32],
                       const uint8_t *info, size_t info_len,
                       uint8_t *okm, size_t okm_len)
{
    if (okm_len > 255 * 32) return -1;

    uint8_t t[32];
    uint8_t counter = 1;
    size_t generated = 0;
    size_t t_len = 0;

    while (generated < okm_len) {
        /* T(i) = HMAC(PRK, T(i-1) | info | counter) */
        size_t msg_len = t_len + info_len + 1;
        uint8_t *msg = (uint8_t *)malloc(msg_len);
        if (!msg) return -5;

        size_t off = 0;
        if (t_len) {
            memcpy(msg, t, t_len);
            off = t_len;
        }
        if (info_len) {
            memcpy(msg + off, info, info_len);
            off += info_len;
        }
        msg[off] = counter;

        if (fossil_cryptic_auth_hmac_sha256(prk, 32, msg, msg_len, t) != 0) {
            free(msg);
            return -2;
        }
        free(msg);

        size_t to_copy = (okm_len - generated > 32) ? 32 : (okm_len - generated);
        memcpy(okm + generated, t, to_copy);
        generated += to_copy;
        t_len = 32;
        counter++;
    }

    fossil_cryptic_util_wipe(t, sizeof(t));
    return 0;
}

int fossil_cryptic_keygen_hkdf_sha256(
    const uint8_t *ikm, size_t ikm_len,
    const uint8_t *salt, size_t salt_len,
    const uint8_t *info, size_t info_len,
    uint8_t *okm, size_t okm_len)
{
    if (!ikm || !okm || ikm_len == 0 || okm_len == 0) return -1;

    uint8_t prk[32];
    if (hkdf_extract(salt, salt_len, ikm, ikm_len, prk) != 0) return -2;
    int rc = hkdf_expand(prk, info, info_len, okm, okm_len);
    fossil_cryptic_util_wipe(prk, sizeof(prk));
    return rc;
}

/* ---------- PBKDF2-HMAC-SHA256 ---------- */

int fossil_cryptic_keygen_pbkdf2_sha256(
    const uint8_t *password, size_t password_len,
    const uint8_t *salt, size_t salt_len,
    uint32_t iterations,
    uint8_t *out, size_t out_len)
{
    if (!password || !salt || !out || password_len == 0 || salt_len == 0 ||
        iterations == 0 || out_len == 0) return -1;

    uint8_t u[32], t[32];
    size_t generated = 0;
    uint32_t block = 1;

    while (generated < out_len) {
        /* U1 = HMAC(password, salt || INT(block)) */
        size_t msg_len = salt_len + 4;
        uint8_t *msg = (uint8_t *)malloc(msg_len);
        if (!msg) return -5;

        memcpy(msg, salt, salt_len);
        msg[salt_len + 0] = (uint8_t)(block >> 24);
        msg[salt_len + 1] = (uint8_t)(block >> 16);
        msg[salt_len + 2] = (uint8_t)(block >>  8);
        msg[salt_len + 3] = (uint8_t)(block);

        if (fossil_cryptic_auth_hmac_sha256(password, password_len, msg, msg_len, u) != 0) {
            free(msg);
            return -2;
        }
        free(msg);
        memcpy(t, u, 32);

        for (uint32_t i = 1; i < iterations; i++) {
            if (fossil_cryptic_auth_hmac_sha256(password, password_len, u, 32, u) != 0)
                return -3;
            for (int j = 0; j < 32; j++)
                t[j] ^= u[j];
        }

        size_t to_copy = (out_len - generated > 32) ? 32 : (out_len - generated);
        memcpy(out + generated, t, to_copy);
        generated += to_copy;
        block++;
    }

    fossil_cryptic_util_wipe(u, sizeof(u));
    fossil_cryptic_util_wipe(t, sizeof(t));
    return 0;
}
