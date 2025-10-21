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
#include "fossil/cryptic/rand.h"
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <stdio.h>

// ===========================================================
// Base64 + Hex encoding helpers
// ===========================================================
static const char base64_chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static void encode_base64(const uint8_t* data, size_t len, char* out, size_t out_len) {
    size_t i = 0, j = 0;
    while (i < len && j + 4 < out_len) {
        uint32_t a = i < len ? data[i++] : 0;
        uint32_t b = i < len ? data[i++] : 0;
        uint32_t c = i < len ? data[i++] : 0;
        uint32_t triple = (a << 16) | (b << 8) | c;

        out[j++] = base64_chars[(triple >> 18) & 0x3F];
        out[j++] = base64_chars[(triple >> 12) & 0x3F];
        out[j++] = (i > len + 1) ? '=' : base64_chars[(triple >> 6) & 0x3F];
        out[j++] = (i > len) ? '=' : base64_chars[triple & 0x3F];
    }
    if (j < out_len) out[j] = '\0';
}

static void u32_to_hex(uint32_t val, char* out, size_t len) {
    snprintf(out, len, "%08x", val);
}

static void u64_to_hex(uint64_t val, char* out, size_t len) {
    snprintf(out, len, "%016llx", (unsigned long long)val);
}

// ===========================================================
// PRNG Implementations
// ===========================================================

// --- Linear Congruential Generator (LCG)
static uint32_t lcg32(uint32_t s) {
    return (1664525u * s + 1013904223u);
}
static uint64_t lcg64(uint64_t s) {
    return (6364136223846793005ull * s + 1ull);
}

// --- XORShift
static uint32_t xor32(uint32_t s) {
    s ^= s << 13;
    s ^= s >> 17;
    s ^= s << 5;
    return s;
}
static uint64_t xor64(uint64_t s) {
    s ^= s << 13;
    s ^= s >> 7;
    s ^= s << 17;
    return s;
}

// --- MixRand (bit mixer)
static uint64_t mix64(uint64_t x) {
    x ^= x >> 33;
    x *= 0xff51afd7ed558ccdull;
    x ^= x >> 33;
    x *= 0xc4ceb9fe1a85ec53ull;
    x ^= x >> 33;
    return x;
}

// ===========================================================
// Main Entry Point
// ===========================================================
int fossil_cryptic_rand_compute(
    const char* algorithm,
    const char* bits,
    const char* base,
    const char* seed,
    char* output, size_t output_len
) {
    if (!algorithm || !bits || !base || !output) return -1;

    int use64 = 0;
    if (strcmp(bits, "u64") == 0) use64 = 1;
    else if (strcmp(bits, "u32") == 0) use64 = 0;
    else if (strcmp(bits, "auto") == 0) use64 = (sizeof(void*) == 8);

    uint64_t state = 0;
    if (seed && *seed) {
        // Simple hash of seed for determinism
        for (size_t i = 0; seed[i]; ++i)
            state = state * 1315423911u + (unsigned char)seed[i];
    } else {
        state = (uint64_t)time(NULL) ^ (uintptr_t)&state;
    }

    uint32_t r32 = 0;
    uint64_t r64 = 0;

    if (strcmp(algorithm, "lcg") == 0 || strcmp(algorithm, "auto") == 0) {
        if (use64) r64 = lcg64(state);
        else r32 = lcg32((uint32_t)state);
    }
    else if (strcmp(algorithm, "xor") == 0) {
        if (use64) r64 = xor64(state);
        else r32 = xor32((uint32_t)state);
    }
    else if (strcmp(algorithm, "mix") == 0) {
        r64 = mix64(state);
        if (!use64) r32 = (uint32_t)(r64 ^ (r64 >> 32));
    }
    else {
        return -2; // unsupported algorithm
    }

    // Encode output
    if (strcmp(base, "hex") == 0 || strcmp(base, "auto") == 0) {
        if (use64) u64_to_hex(r64, output, output_len);
        else u32_to_hex(r32, output, output_len);
    }
    else if (strcmp(base, "base64") == 0) {
        uint8_t buffer[8];
        size_t len = use64 ? 8 : 4;
        if (use64) for (int i = 0; i < 8; i++) buffer[7 - i] = (r64 >> (i * 8)) & 0xFF;
        else for (int i = 0; i < 4; i++) buffer[3 - i] = (r32 >> (i * 8)) & 0xFF;
        encode_base64(buffer, len, output, output_len);
    }
    else {
        return -3; // unsupported base
    }

    return 0;
}
