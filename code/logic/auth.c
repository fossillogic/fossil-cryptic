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
#include "fossil/cryptic/auth.h"
#include "fossil/cryptic/hash.h"
#include "fossil/cryptic/util.h"
#include <string.h>
#include <stdlib.h>

#define SHA256_BLOCK 64
#define BLAKE2B_BLOCK 128

int fossil_cryptic_auth_hmac_sha256(
    const uint8_t *key, size_t key_len,
    const void *msg, size_t msg_len,
    uint8_t out[32])
{
    if (!out)
        return -1;
    if (key_len && !key)
        return -1;
    if (msg_len && !msg)
        return -1;

    uint8_t k[SHA256_BLOCK];
    uint8_t ipad[SHA256_BLOCK];
    uint8_t opad[SHA256_BLOCK];
    uint8_t tk[32];

    memset(k, 0, SHA256_BLOCK);

    if (key_len > SHA256_BLOCK)
    {
        if (fossil_cryptic_hash_sha256(key, key_len, tk) != 0)
            return -2;
        memcpy(k, tk, 32);
        fossil_cryptic_util_wipe(tk, sizeof(tk));
    }
    else
    {
        memcpy(k, key, key_len);
    }

    for (int i = 0; i < SHA256_BLOCK; i++)
    {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5c;
    }

    /* inner = H(ipad || msg) */
    uint8_t *inner = (uint8_t *)malloc(SHA256_BLOCK + msg_len);
    if (!inner)
        return -5;
    memcpy(inner, ipad, SHA256_BLOCK);
    if (msg_len)
        memcpy(inner + SHA256_BLOCK, msg, msg_len);

    uint8_t inner_hash[32];
    if (fossil_cryptic_hash_sha256(inner, SHA256_BLOCK + msg_len, inner_hash) != 0)
    {
        free(inner);
        return -3;
    }
    free(inner);

    /* outer = H(opad || inner_hash) */
    uint8_t outer[SHA256_BLOCK + 32];
    memcpy(outer, opad, SHA256_BLOCK);
    memcpy(outer + SHA256_BLOCK, inner_hash, 32);

    int rc = fossil_cryptic_hash_sha256(outer, SHA256_BLOCK + 32, out);

    fossil_cryptic_util_wipe(k, sizeof(k));
    fossil_cryptic_util_wipe(ipad, sizeof(ipad));
    fossil_cryptic_util_wipe(opad, sizeof(opad));
    fossil_cryptic_util_wipe(inner_hash, sizeof(inner_hash));
    fossil_cryptic_util_wipe(outer, sizeof(outer));

    return rc;
}

int fossil_cryptic_auth_hmac_blake2b_512(
    const uint8_t *key, size_t key_len,
    const void *msg, size_t msg_len,
    uint8_t out[64])
{
    if (!out)
        return -1;
    if (key_len && !key)
        return -1;
    if (msg_len && !msg)
        return -1;

    uint8_t k[BLAKE2B_BLOCK];
    uint8_t ipad[BLAKE2B_BLOCK];
    uint8_t opad[BLAKE2B_BLOCK];
    uint8_t tk[64];

    memset(k, 0, BLAKE2B_BLOCK);

    if (key_len > BLAKE2B_BLOCK)
    {
        if (fossil_cryptic_hash_blake2b_512(key, key_len, tk) != 0)
            return -2;
        memcpy(k, tk, 64);
        fossil_cryptic_util_wipe(tk, sizeof(tk));
    }
    else
    {
        memcpy(k, key, key_len);
    }

    for (int i = 0; i < BLAKE2B_BLOCK; i++)
    {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5c;
    }

    uint8_t *inner = (uint8_t *)malloc(BLAKE2B_BLOCK + msg_len);
    if (!inner)
        return -5;
    memcpy(inner, ipad, BLAKE2B_BLOCK);
    if (msg_len)
        memcpy(inner + BLAKE2B_BLOCK, msg, msg_len);

    uint8_t inner_hash[64];
    if (fossil_cryptic_hash_blake2b_512(inner, BLAKE2B_BLOCK + msg_len, inner_hash) != 0)
    {
        free(inner);
        return -3;
    }
    free(inner);

    uint8_t outer[BLAKE2B_BLOCK + 64];
    memcpy(outer, opad, BLAKE2B_BLOCK);
    memcpy(outer + BLAKE2B_BLOCK, inner_hash, 64);

    int rc = fossil_cryptic_hash_blake2b_512(outer, BLAKE2B_BLOCK + 64, out);

    fossil_cryptic_util_wipe(k, sizeof(k));
    fossil_cryptic_util_wipe(ipad, sizeof(ipad));
    fossil_cryptic_util_wipe(opad, sizeof(opad));
    fossil_cryptic_util_wipe(inner_hash, sizeof(inner_hash));
    fossil_cryptic_util_wipe(outer, sizeof(outer));

    return rc;
}
