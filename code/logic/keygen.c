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
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#else
#include <errno.h>
#include <unistd.h>
#endif

// ===========================================================
// Helpers (same base64 + hex from cryptic_hash)
// ===========================================================
static const char base64_chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static void encode_base64(const uint8_t* data, size_t len, char* out, size_t out_len) {
    size_t i = 0, j = 0;
    while (i < len && j + 4 < out_len) {
        size_t remaining = len - i;
        uint32_t a = data[i++];
        uint32_t b = remaining > 1 ? data[i++] : 0;
        uint32_t c = remaining > 2 ? data[i++] : 0;
        uint32_t triple = (a << 16) | (b << 8) | c;

        out[j++] = base64_chars[(triple >> 18) & 0x3F];
        out[j++] = base64_chars[(triple >> 12) & 0x3F];
        out[j++] = remaining > 1 ? base64_chars[(triple >> 6) & 0x3F] : '=';
        out[j++] = remaining > 2 ? base64_chars[triple & 0x3F] : '=';
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

// SHA-256 and HKDF are implemented locally to avoid an OpenSSL dependency.
typedef struct {
    uint32_t state[8];
    uint64_t bit_count;
    uint8_t block[64];
    size_t block_len;
} sha256_context;

static const uint32_t sha256_k[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static uint32_t rotate_right(uint32_t value, unsigned int amount) {
    return (value >> amount) | (value << (32 - amount));
}

static void sha256_transform(sha256_context* ctx, const uint8_t block[64]) {
    uint32_t w[64];
    for (size_t i = 0; i < 16; ++i)
        w[i] = ((uint32_t)block[i * 4] << 24) | ((uint32_t)block[i * 4 + 1] << 16) |
               ((uint32_t)block[i * 4 + 2] << 8) | block[i * 4 + 3];
    for (size_t i = 16; i < 64; ++i) {
        uint32_t s0 = rotate_right(w[i - 15], 7) ^ rotate_right(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = rotate_right(w[i - 2], 17) ^ rotate_right(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint32_t a = ctx->state[0], b = ctx->state[1], c = ctx->state[2], d = ctx->state[3];
    uint32_t e = ctx->state[4], f = ctx->state[5], g = ctx->state[6], h = ctx->state[7];
    for (size_t i = 0; i < 64; ++i) {
        uint32_t s1 = rotate_right(e, 6) ^ rotate_right(e, 11) ^ rotate_right(e, 25);
        uint32_t choice = (e & f) ^ (~e & g);
        uint32_t t1 = h + s1 + choice + sha256_k[i] + w[i];
        uint32_t s0 = rotate_right(a, 2) ^ rotate_right(a, 13) ^ rotate_right(a, 22);
        uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = s0 + majority;
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

static void sha256_init(sha256_context* ctx) {
    static const uint32_t initial[8] = {
        0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
        0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
    };
    memcpy(ctx->state, initial, sizeof(initial));
    ctx->bit_count = 0;
    ctx->block_len = 0;
}

static void sha256_update(sha256_context* ctx, const uint8_t* data, size_t len) {
    ctx->bit_count += (uint64_t)len * 8;
    while (len) {
        size_t take = sizeof(ctx->block) - ctx->block_len;
        if (take > len) take = len;
        memcpy(ctx->block + ctx->block_len, data, take);
        ctx->block_len += take;
        data += take;
        len -= take;
        if (ctx->block_len == sizeof(ctx->block)) {
            sha256_transform(ctx, ctx->block);
            ctx->block_len = 0;
        }
    }
}

static void sha256_final(sha256_context* ctx, uint8_t digest[32]) {
    uint64_t bits = ctx->bit_count;
    ctx->block[ctx->block_len++] = 0x80;
    if (ctx->block_len > 56) {
        memset(ctx->block + ctx->block_len, 0, 64 - ctx->block_len);
        sha256_transform(ctx, ctx->block);
        ctx->block_len = 0;
    }
    memset(ctx->block + ctx->block_len, 0, 56 - ctx->block_len);
    for (size_t i = 0; i < 8; ++i) ctx->block[63 - i] = (uint8_t)(bits >> (i * 8));
    sha256_transform(ctx, ctx->block);
    for (size_t i = 0; i < 8; ++i) {
        digest[i * 4] = (uint8_t)(ctx->state[i] >> 24);
        digest[i * 4 + 1] = (uint8_t)(ctx->state[i] >> 16);
        digest[i * 4 + 2] = (uint8_t)(ctx->state[i] >> 8);
        digest[i * 4 + 3] = (uint8_t)ctx->state[i];
    }
}

static void hmac_sha256(const uint8_t* key, size_t key_len, const uint8_t* data,
                        size_t data_len, uint8_t digest[32]) {
    uint8_t key_block[64] = {0}, inner_pad[64], outer_pad[64], inner_hash[32];
    if (key_len > sizeof(key_block)) {
        sha256_context hash;
        sha256_init(&hash);
        sha256_update(&hash, key, key_len);
        sha256_final(&hash, key_block);
    } else if (key_len) {
        memcpy(key_block, key, key_len);
    }
    for (size_t i = 0; i < sizeof(key_block); ++i) {
        inner_pad[i] = key_block[i] ^ 0x36;
        outer_pad[i] = key_block[i] ^ 0x5c;
    }
    sha256_context hash;
    sha256_init(&hash);
    sha256_update(&hash, inner_pad, sizeof(inner_pad));
    sha256_update(&hash, data, data_len);
    sha256_final(&hash, inner_hash);
    sha256_init(&hash);
    sha256_update(&hash, outer_pad, sizeof(outer_pad));
    sha256_update(&hash, inner_hash, sizeof(inner_hash));
    sha256_final(&hash, digest);
}

static void hkdf_sha256(const uint8_t* seed, size_t seed_len, uint8_t key[32]) {
    static const uint8_t info[] = "Fossil Logic key derivation v1";
    uint8_t salt[32] = {0}, pseudorandom_key[32], expand_input[sizeof(info)];
    hmac_sha256(salt, sizeof(salt), seed, seed_len, pseudorandom_key);
    memcpy(expand_input, info, sizeof(info) - 1);
    expand_input[sizeof(info) - 1] = 1;
    hmac_sha256(pseudorandom_key, sizeof(pseudorandom_key), expand_input,
                sizeof(expand_input), key);
}

static int secure_random_bytes(uint8_t* output, size_t len) {
#ifdef _WIN32
    return BCryptGenRandom(NULL, output, (ULONG)len, BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0 ? 0 : -1;
#else
    FILE* source = fopen("/dev/urandom", "rb");
    if (!source) return -1;
    size_t got = fread(output, 1, len, source);
    int ok = (got == len && fclose(source) == 0) ? 0 : -1;
    if (got != len) fclose(source);
    return ok;
#endif
}

static int encode_key(const uint8_t key[32], const char* base, char* output, size_t output_len) {
    if (strcmp(base, "hex") == 0 || strcmp(base, "auto") == 0) {
        if (output_len < 65) return -1;
        for (size_t i = 0; i < 32; ++i)
            snprintf(output + i * 2, output_len - i * 2, "%02x", key[i]);
        output[64] = '\0';
        return 0;
    }
    if (strcmp(base, "base64") == 0) {
        if (output_len < 45) return -1;
        encode_base64(key, 32, output, output_len);
        return 0;
    }
    return -2;
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

    if (strcmp(algorithm, "hkdf") == 0) {
        uint8_t random_seed[32];
        uint8_t key[32];
        const uint8_t* key_seed = (const uint8_t*)seed;
        size_t key_seed_len = strlen(seed);

        if (strcmp(seed, "random") == 0) {
            if (secure_random_bytes(random_seed, sizeof(random_seed)) != 0) return -4;
            key_seed = random_seed;
            key_seed_len = sizeof(random_seed);
        }

        hkdf_sha256(key_seed, key_seed_len, key);
        return encode_key(key, base, output, output_len);
    }

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
