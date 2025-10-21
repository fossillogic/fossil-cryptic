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
#include "fossil/cryptic/keygen.h"
#include <string.h>
#include <stdint.h>
#include <stdio.h>

// ===========================================================
// Helpers (same base64 + hex from cryptic_hash)
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
// Lightweight Hash Primitives (internal use)
// ===========================================================
static uint32_t fnv32(const void* data, size_t len) {
    const uint8_t* b = (const uint8_t*)data;
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < len; i++) {
        h ^= b[i];
        h *= 16777619u;
    }
    return h;
}

static uint64_t fnv64(const void* data, size_t len) {
    const uint8_t* b = (const uint8_t*)data;
    uint64_t h = 14695981039346656037ull;
    for (size_t i = 0; i < len; i++) {
        h ^= b[i];
        h *= 1099511628211ull;
    }
    return h;
}

static uint32_t crc32(const void* data, size_t len) {
    const uint8_t* bytes = (const uint8_t*)data;
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < len; i++) {
        crc ^= bytes[i];
        for (int j = 0; j < 8; j++)
            crc = (crc >> 1) ^ (0xEDB88320 & -(crc & 1));
    }
    return ~crc;
}

static uint64_t mix64(const void* data, size_t len) {
    const uint8_t* b = (const uint8_t*)data;
    uint64_t h = 0xC0FFEEBEEFC0FFEEull;
    for (size_t i = 0; i < len; i++) {
        h ^= ((uint64_t)b[i] << ((i % 8) * 8));
        h = (h << 13) | (h >> 51);
        h *= 0x9E3779B97F4A7C15ull; // golden ratio mix
    }
    return h;
}

// ===========================================================
// Main Entry Point
// ===========================================================
int fossil_cryptic_keygen_compute(
    const char* algorithm,
    const char* bits,
    const char* base,
    const char* seed,
    char* output, size_t output_len
) {
    if (!algorithm || !bits || !base || !seed || !output) return -1;

    int use64 = 0;
    if (strcmp(bits, "u64") == 0) use64 = 1;
    else if (strcmp(bits, "u32") == 0) use64 = 0;
    else if (strcmp(bits, "auto") == 0) use64 = (strlen(seed) > 8); // heuristic

    uint32_t h32 = 0;
    uint64_t h64 = 0;

    // Algorithm selection
    if (strcmp(algorithm, "fnv") == 0 || strcmp(algorithm, "auto") == 0) {
        if (use64) h64 = fnv64(seed, strlen(seed));
        else h32 = fnv32(seed, strlen(seed));
    }
    else if (strcmp(algorithm, "crc") == 0) {
        h32 = crc32(seed, strlen(seed));
        if (use64) h64 = ((uint64_t)h32 << 32) | h32;
    }
    else if (strcmp(algorithm, "mix") == 0) {
        h64 = mix64(seed, strlen(seed));
        if (!use64) h32 = (uint32_t)(h64 ^ (h64 >> 32));
    }
    else {
        return -2; // unsupported algorithm
    }

    // Encoding output
    if (strcmp(base, "hex") == 0 || strcmp(base, "auto") == 0) {
        if (use64) u64_to_hex(h64, output, output_len);
        else u32_to_hex(h32, output, output_len);
    }
    else if (strcmp(base, "base64") == 0) {
        uint8_t buffer[8];
        size_t len = use64 ? 8 : 4;
        if (use64) for (int i = 0; i < 8; i++) buffer[7 - i] = (h64 >> (i * 8)) & 0xFF;
        else for (int i = 0; i < 4; i++) buffer[3 - i] = (h32 >> (i * 8)) & 0xFF;
        encode_base64(buffer, len, output, output_len);
    }
    else {
        return -3; // unsupported base
    }

    return 0;
}
