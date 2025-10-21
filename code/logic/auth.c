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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// HMAC block size for 64-bit hash (max 64 bytes)
#define HMAC_BLOCK_SIZE 64

int fossil_cryptic_auth_compute(
    const char* algorithm,
    const char* bits,
    const char* base,
    const char* key,
    const void* input, size_t input_len,
    char* output, size_t output_len
) {
    if (!algorithm || !bits || !base || !key || !input || !output) return -1;

    size_t key_len = strlen(key);
    uint8_t k_ipad[HMAC_BLOCK_SIZE];
    uint8_t k_opad[HMAC_BLOCK_SIZE];
    uint8_t key_hash[HMAC_BLOCK_SIZE];
    char key_hash_str[2 * HMAC_BLOCK_SIZE + 1];
    size_t hash_size = 0;

    if (strcmp(bits, "u64") == 0) hash_size = 8;
    else if (strcmp(bits, "u32") == 0) hash_size = 4;
    else return -1;

    // Step 1: If key > block size, hash it first
    if (key_len > HMAC_BLOCK_SIZE) {
        if (fossil_cryptic_hash_compute(algorithm, bits, "hex", key_hash_str, sizeof(key_hash_str), key, key_len) != 0)
            return -2;

        // Convert hex string to bytes
        for (size_t i = 0; i < hash_size; i++) {
            unsigned int byte = 0;
            if (sscanf(key_hash_str + i * 2, "%2x", &byte) != 1)
                return -2;
            key_hash[i] = (uint8_t)byte;
        }
        key_len = hash_size;
    } else {
        memset(key_hash, 0, HMAC_BLOCK_SIZE);
        memcpy(key_hash, key, key_len);
    }

    // Step 2: Prepare inner and outer padded keys
    memset(k_ipad, 0x36, HMAC_BLOCK_SIZE);
    memset(k_opad, 0x5c, HMAC_BLOCK_SIZE);
    for (size_t i = 0; i < HMAC_BLOCK_SIZE; i++) {
        k_ipad[i] ^= key_hash[i];
        k_opad[i] ^= key_hash[i];
    }

    // Step 3: Compute inner hash: hash(inner_pad || input)
    uint8_t* inner_buffer = (uint8_t*)malloc(HMAC_BLOCK_SIZE + input_len);
    if (!inner_buffer) return -5;
    memcpy(inner_buffer, k_ipad, HMAC_BLOCK_SIZE);
    memcpy(inner_buffer + HMAC_BLOCK_SIZE, input, input_len);

    char inner_hash_str[2 * HMAC_BLOCK_SIZE + 1];
    if (fossil_cryptic_hash_compute(algorithm, bits, "hex", inner_hash_str, sizeof(inner_hash_str),
                             inner_buffer, HMAC_BLOCK_SIZE + input_len) != 0) {
        free(inner_buffer);
        return -3;
    }
    free(inner_buffer);

    // Convert inner hash string to bytes
    uint8_t inner_hash_bytes[HMAC_BLOCK_SIZE];
    for (size_t i = 0; i < hash_size; i++) {
        unsigned int byte = 0;
        if (sscanf(inner_hash_str + i * 2, "%2x", &byte) != 1)
            return -3;
        inner_hash_bytes[i] = (uint8_t)byte;
    }

    // Step 4: Compute outer hash: hash(outer_pad || inner_hash)
    uint8_t outer_buffer[HMAC_BLOCK_SIZE + HMAC_BLOCK_SIZE];
    memcpy(outer_buffer, k_opad, HMAC_BLOCK_SIZE);
    memcpy(outer_buffer + HMAC_BLOCK_SIZE, inner_hash_bytes, hash_size);

    // Final HMAC
    int rc = fossil_cryptic_hash_compute(
        algorithm, bits, base, output, output_len,
        outer_buffer, HMAC_BLOCK_SIZE + hash_size
    );
    if (rc != 0) return rc;

    // Ensure output is null-terminated if base is "hex" or "base64"
    if (output_len > 0)
        output[output_len - 1] = '\0';

    // Check output buffer size (simulate failure if too small)
    if (strlen(output) == 0 || output_len < 2)
        return -6;

    return 0;
}
