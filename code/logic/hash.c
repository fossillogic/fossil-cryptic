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
#include "fossil/cryptic/hash.h"
#include <string.h>
#include <stdio.h>

// =======================================================
// Helper: Bit extraction and conversion
// =======================================================
static void u32_to_hex(uint32_t val, char* out, size_t len) {
    snprintf(out, len, "%08x", val);
}

static void u64_to_hex(uint64_t val, char* out, size_t len) {
    snprintf(out, len, "%016llx", (unsigned long long)val);
}

// Convert uint32_t to decimal string
static void u32_to_dec(uint32_t val, char* out, size_t len) {
    snprintf(out, len, "%u", val);
}

// Convert uint64_t to decimal string
static void u64_to_dec(uint64_t val, char* out, size_t len) {
    snprintf(out, len, "%llu", (unsigned long long)val);
}

// Convert uint32_t to octal string
static void u32_to_oct(uint32_t val, char* out, size_t len) {
    snprintf(out, len, "%o", val);
}

// Convert uint64_t to octal string
static void u64_to_oct(uint64_t val, char* out, size_t len) {
    snprintf(out, len, "%llo", (unsigned long long)val);
}

// Convert uint32_t to binary string
static void u32_to_bin(uint32_t val, char* out, size_t len) {
    size_t i = 0;
    for (int bit = 31; bit >= 0 && i + 1 < len; --bit) {
        out[i++] = (val & (1u << bit)) ? '1' : '0';
    }
    out[i] = '\0';
}

// Convert uint64_t to binary string
static void u64_to_bin(uint64_t val, char* out, size_t len) {
    size_t i = 0;
    for (int bit = 63; bit >= 0 && i + 1 < len; --bit) {
        out[i++] = (val & (1ull << bit)) ? '1' : '0';
    }
    out[i] = '\0';
}

// =======================================================
// Simple Hash Functions
// =======================================================

// CRC32 (standard polynomial)
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

static uint64_t crc64(const void* data, size_t len) {
    const uint8_t* bytes = (const uint8_t*)data;
    uint64_t crc = 0xFFFFFFFFFFFFFFFFull;
    for (size_t i = 0; i < len; i++) {
        crc ^= bytes[i];
        for (int j = 0; j < 8; j++)
            crc = (crc >> 1) ^ (0xC96C5795D7870F42ull & -(crc & 1));
    }
    return ~crc;
}

// FNV-1a 32-bit
static uint32_t fnv32(const void* data, size_t len) {
    const uint8_t* bytes = (const uint8_t*)data;
    uint32_t hash = 2166136261u;
    for (size_t i = 0; i < len; i++) {
        hash ^= bytes[i];
        hash *= 16777619u;
    }
    return hash;
}

// FNV-1a 64-bit
static uint64_t fnv64(const void* data, size_t len) {
    const uint8_t* bytes = (const uint8_t*)data;
    uint64_t hash = 14695981039346656037ull;
    for (size_t i = 0; i < len; i++) {
        hash ^= bytes[i];
        hash *= 1099511628211ull;
    }
    return hash;
}

// DJB2
static uint32_t djb2(const void* data, size_t len) {
    const uint8_t* bytes = (const uint8_t*)data;
    uint32_t hash = 5381;
    for (size_t i = 0; i < len; i++)
        hash = ((hash << 5) + hash) + bytes[i]; // hash * 33 + c
    return hash;
}

// SDBM
static uint32_t sdbm(const void* data, size_t len) {
    const uint8_t* bytes = (const uint8_t*)data;
    uint32_t hash = 0;
    for (size_t i = 0; i < len; i++)
        hash = bytes[i] + (hash << 6) + (hash << 16) - hash;
    return hash;
}

// XOR simple
static uint32_t xor_hash(const void* data, size_t len) {
    const uint8_t* bytes = (const uint8_t*)data;
    uint32_t hash = 0;
    for (size_t i = 0; i < len; i++)
        hash ^= bytes[i];
    return hash;
}

// =======================================================
// Advanced Hash Functions
// =======================================================

// MurmurHash3 32-bit
static uint32_t murmur3_32(const void* key, size_t len, uint32_t seed) {
    const uint8_t* data = (const uint8_t*)key;
    const int nblocks = len / 4;
    uint32_t h1 = seed;

    const uint32_t c1 = 0xcc9e2d51;
    const uint32_t c2 = 0x1b873593;

    // body
    const uint32_t* blocks = (const uint32_t*)(data + nblocks * 4);
    for (int i = -nblocks; i; i++) {
        uint32_t k1 = blocks[i];
        k1 *= c1;
        k1 = (k1 << 15) | (k1 >> (32 - 15));
        k1 *= c2;

        h1 ^= k1;
        h1 = (h1 << 13) | (h1 >> (32 - 13));
        h1 = h1 * 5 + 0xe6546b64;
    }

    // tail
    const uint8_t* tail = (const uint8_t*)(data + nblocks * 4);
    uint32_t k1 = 0;
    switch (len & 3) {
        case 3: k1 ^= tail[2] << 16; /* fall through */
        case 2: k1 ^= tail[1] << 8;  /* fall through */
        case 1: k1 ^= tail[0];
                k1 *= c1;
                k1 = (k1 << 15) | (k1 >> (32 - 15));
                k1 *= c2;
                h1 ^= k1;
        break;
    }

    // finalization
    h1 ^= len;
    h1 ^= (h1 >> 16);
    h1 *= 0x85ebca6b;
    h1 ^= (h1 >> 13);
    h1 *= 0xc2b2ae35;
    h1 ^= (h1 >> 16);

    return h1;
}

// MurmurHash3 64-bit (returns lower 64 bits of MurmurHash3_x64_128)
static uint64_t murmur3_64(const void* key, size_t len, uint32_t seed) {
    const uint8_t* data = (const uint8_t*)key;
    const int nblocks = len / 16;
    uint64_t h1 = seed;
    uint64_t h2 = seed;

    const uint64_t c1 = 0x87c37b91114253d5ull;
    const uint64_t c2 = 0x4cf5ad432745937full;

    // body
    const uint64_t* blocks = (const uint64_t*)(data);
    for (int i = 0; i < nblocks; i++) {
        uint64_t k1 = blocks[i * 2 + 0];
        uint64_t k2 = blocks[i * 2 + 1];

        k1 *= c1; k1 = (k1 << 31) | (k1 >> (64 - 31)); k1 *= c2; h1 ^= k1;
        h1 = (h1 << 27) | (h1 >> (64 - 27)); h1 += h2; h1 = h1 * 5 + 0x52dce729;

        k2 *= c2; k2 = (k2 << 33) | (k2 >> (64 - 33)); k2 *= c1; h2 ^= k2;
        h2 = (h2 << 31) | (h2 >> (64 - 31)); h2 += h1; h2 = h2 * 5 + 0x38495ab5;
    }

    // tail
    const uint8_t* tail = (const uint8_t*)(data + nblocks * 16);
    uint64_t k1 = 0, k2 = 0;
    switch (len & 15) {
        case 15: k2 ^= ((uint64_t)tail[14]) << 48; /* fall through */
        case 14: k2 ^= ((uint64_t)tail[13]) << 40; /* fall through */
        case 13: k2 ^= ((uint64_t)tail[12]) << 32; /* fall through */
        case 12: k2 ^= ((uint64_t)tail[11]) << 24; /* fall through */
        case 11: k2 ^= ((uint64_t)tail[10]) << 16; /* fall through */
        case 10: k2 ^= ((uint64_t)tail[9]) << 8;   /* fall through */
        case 9:  k2 ^= ((uint64_t)tail[8]) << 0;
                 k2 *= c2; k2 = (k2 << 33) | (k2 >> (64 - 33)); k2 *= c1; h2 ^= k2;
            break;
        case 8:  k1 ^= ((uint64_t)tail[7]) << 56; /* fall through */
        case 7:  k1 ^= ((uint64_t)tail[6]) << 48; /* fall through */
        case 6:  k1 ^= ((uint64_t)tail[5]) << 40; /* fall through */
        case 5:  k1 ^= ((uint64_t)tail[4]) << 32; /* fall through */
        case 4:  k1 ^= ((uint64_t)tail[3]) << 24; /* fall through */
        case 3:  k1 ^= ((uint64_t)tail[2]) << 16; /* fall through */
        case 2:  k1 ^= ((uint64_t)tail[1]) << 8;  /* fall through */
        case 1:  k1 ^= ((uint64_t)tail[0]) << 0;
                 k1 *= c1; k1 = (k1 << 31) | (k1 >> (64 - 31)); k1 *= c2; h1 ^= k1;
            break;
    }

    // finalization
    h1 ^= len;
    h2 ^= len;
    h1 += h2;
    h2 += h1;

    // fmix64
    h1 ^= h1 >> 33;
    h1 *= 0xff51afd7ed558ccdull;
    h1 ^= h1 >> 33;
    h1 *= 0xc4ceb9fe1a85ec53ull;
    h1 ^= h1 >> 33;

    h2 ^= h2 >> 33;
    h2 *= 0xff51afd7ed558ccdull;
    h2 ^= h2 >> 33;
    h2 *= 0xc4ceb9fe1a85ec53ull;
    h2 ^= h2 >> 33;

    h1 += h2;
    // Only return h1 for 64-bit hash
    return h1;
}

// CityHash32 (simplified, not full Google implementation)
static uint32_t cityhash32(const void* data, size_t len) {
    const uint8_t* s = (const uint8_t*)data;
    uint32_t h = (uint32_t)len, g, f;
    if (len == 0) return 0;
    h += s[0];
    for (size_t i = 1; i < len; ++i) {
        g = f = h;
        g <<= 5; f >>= 2;
        h ^= (g + f + s[i]);
    }
    return h;
}

// CityHash64 (simplified, not full Google implementation)
static uint64_t cityhash64(const void* data, size_t len) {
    const uint8_t* s = (const uint8_t*)data;
    uint64_t h = (uint64_t)len, g, f;
    if (len == 0) return 0;
    h += s[0];
    for (size_t i = 1; i < len; ++i) {
        g = f = h;
        g <<= 7; f >>= 3;
        h ^= (g + f + s[i]);
    }
    return h;
}

// XXHash32 (very simplified, not optimized)
static uint32_t xxhash32(const void* data, size_t len, uint32_t seed) {
    const uint8_t* p = (const uint8_t*)data;
    uint32_t h = seed + (uint32_t)len;
    for (size_t i = 0; i < len; ++i) {
        h += p[i] * 374761393U;
        h = (h << 13) | (h >> (32 - 13));
        h *= 2654435761U;
    }
    h ^= h >> 15;
    h *= 2246822519U;
    h ^= h >> 13;
    h *= 3266489917U;
    h ^= h >> 16;
    return h;
}

// XXHash64 (very simplified, not optimized)
static uint64_t xxhash64(const void* data, size_t len, uint64_t seed) {
    const uint8_t* p = (const uint8_t*)data;
    uint64_t h = seed + (uint64_t)len;
    for (size_t i = 0; i < len; ++i) {
        h += p[i] * 11400714785074694791ull;
        h = (h << 31) | (h >> (64 - 31));
        h *= 14029467366897019727ull;
    }
    h ^= h >> 33;
    h *= 1609587929392839161ull;
    h ^= h >> 29;
    h *= 9650029242287828579ull;
    h ^= h >> 32;
    return h;
}

// BLAKE2b-512, as specified by RFC 7693.
static uint64_t blake2b_rotr64(uint64_t value, unsigned int shift) {
    return (value >> shift) | (value << (64 - shift));
}

static uint64_t blake2b_load64(const uint8_t* input) {
    uint64_t value = 0;
    for (unsigned int i = 0; i < 8; ++i)
        value |= (uint64_t)input[i] << (8 * i);
    return value;
}

static void blake2b_g(uint64_t v[16], int a, int b, int c, int d,
                      uint64_t x, uint64_t y) {
    v[a] = v[a] + v[b] + x;
    v[d] = blake2b_rotr64(v[d] ^ v[a], 32);
    v[c] += v[d];
    v[b] = blake2b_rotr64(v[b] ^ v[c], 24);
    v[a] = v[a] + v[b] + y;
    v[d] = blake2b_rotr64(v[d] ^ v[a], 16);
    v[c] += v[d];
    v[b] = blake2b_rotr64(v[b] ^ v[c], 63);
}

static void blake2b_compress(uint64_t h[8], const uint8_t block[128],
                             uint64_t count, int last) {
    static const uint64_t iv[8] = {
        0x6a09e667f3bcc908ull, 0xbb67ae8584caa73bull,
        0x3c6ef372fe94f82bull, 0xa54ff53a5f1d36f1ull,
        0x510e527fade682d1ull, 0x9b05688c2b3e6c1full,
        0x1f83d9abfb41bd6bull, 0x5be0cd19137e2179ull
    };
    static const uint8_t sigma[12][16] = {
        { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15},
        {14,10, 4, 8, 9,15,13, 6, 1,12, 0, 2,11, 7, 5, 3},
        {11, 8,12, 0, 5, 2,15,13,10,14, 3, 6, 7, 1, 9, 4},
        { 7, 9, 3, 1,13,12,11,14, 2, 6, 5,10, 4, 0,15, 8},
        { 9, 0, 5, 7, 2, 4,10,15,14, 1,11,12, 6, 8, 3,13},
        { 2,12, 6,10, 0,11, 8, 3, 4,13, 7, 5,15,14, 1, 9},
        {12, 5, 1,15,14,13, 4,10, 0, 7, 6, 3, 9, 2, 8,11},
        {13,11, 7,14,12, 1, 3, 9, 5, 0,15, 4, 8, 6, 2,10},
        { 6,15,14, 9,11, 3, 0, 8,12, 2,13, 7, 1, 4,10, 5},
        {10, 2, 8, 4, 7, 6, 1, 5,15,11, 9,14, 3,12,13, 0},
        { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15},
        {14,10, 4, 8, 9,15,13, 6, 1,12, 0, 2,11, 7, 5, 3}
    };
    uint64_t m[16], v[16];

    for (int i = 0; i < 16; ++i)
        m[i] = blake2b_load64(block + i * 8);
    for (int i = 0; i < 8; ++i) {
        v[i] = h[i];
        v[i + 8] = iv[i];
    }
    v[12] ^= count;
    if (last)
        v[14] = ~v[14];

    for (int round = 0; round < 12; ++round) {
        const uint8_t* s = sigma[round];
        blake2b_g(v, 0, 4, 8,12, m[s[0]],  m[s[1]]);
        blake2b_g(v, 1, 5, 9,13, m[s[2]],  m[s[3]]);
        blake2b_g(v, 2, 6,10,14, m[s[4]],  m[s[5]]);
        blake2b_g(v, 3, 7,11,15, m[s[6]],  m[s[7]]);
        blake2b_g(v, 0, 5,10,15, m[s[8]],  m[s[9]]);
        blake2b_g(v, 1, 6,11,12, m[s[10]], m[s[11]]);
        blake2b_g(v, 2, 7, 8,13, m[s[12]], m[s[13]]);
        blake2b_g(v, 3, 4, 9,14, m[s[14]], m[s[15]]);
    }

    for (int i = 0; i < 8; ++i)
        h[i] ^= v[i] ^ v[i + 8];
}

static void blake2b_512(const void* input, size_t len, uint8_t digest[64]) {
    static const uint64_t iv[8] = {
        0x6a09e667f3bcc908ull, 0xbb67ae8584caa73bull,
        0x3c6ef372fe94f82bull, 0xa54ff53a5f1d36f1ull,
        0x510e527fade682d1ull, 0x9b05688c2b3e6c1full,
        0x1f83d9abfb41bd6bull, 0x5be0cd19137e2179ull
    };
    uint64_t h[8];
    const uint8_t* data = (const uint8_t*)input;
    uint8_t block[128] = {0};
    size_t offset = 0;

    memcpy(h, iv, sizeof(h));
    h[0] ^= 0x01010040ull; // unkeyed, 64-byte digest
    while (len - offset > sizeof(block)) {
        blake2b_compress(h, data + offset, (uint64_t)(offset + sizeof(block)), 0);
        offset += sizeof(block);
    }

    size_t remaining = len - offset;
    if (remaining)
        memcpy(block, data + offset, remaining);
    blake2b_compress(h, block, (uint64_t)len, 1);
    for (int i = 0; i < 8; ++i) {
        for (int j = 0; j < 8; ++j)
            digest[i * 8 + j] = (uint8_t)(h[i] >> (8 * j));
    }
}

// =======================================================
// Main Function
// =======================================================
int fossil_cryptic_hash_compute(
    const char* algorithm,
    const char* bits,
    const char* base,
    char* output, size_t output_len,
    const void* input, size_t input_len
) {
    if (!algorithm || !bits || !base || !output || (!input && input_len != 0)) return -1;

    // The default and explicit BLAKE2b path return the full 512-bit digest.
    if (strcmp(algorithm, "auto") == 0 || strcmp(algorithm, "blake2b") == 0) {
        if (strcmp(base, "hex") != 0 && strcmp(base, "auto") != 0) return -4;
        if (output_len < 129) return -5;

        static const char hex[] = "0123456789abcdef";
        uint8_t digest[64];
        blake2b_512(input, input_len, digest);
        for (size_t i = 0; i < sizeof(digest); ++i) {
            output[i * 2] = hex[digest[i] >> 4];
            output[i * 2 + 1] = hex[digest[i] & 0x0f];
        }
        output[128] = '\0';
        return 0;
    }

    int use_u64 = 0;
    if (strcmp(bits, "u64") == 0) use_u64 = 1;
    else if (strcmp(bits, "u32") == 0) use_u64 = 0;
    else if (strcmp(bits, "auto") == 0) use_u64 = 0; // default u32
    else return -2; // unsupported bits

    // ===================================================
    // Select Algorithm
    // ===================================================
    uint32_t hash32 = 0;
    uint64_t hash64 = 0;

    if (strcmp(algorithm, "crc32") == 0) {
        hash32 = crc32(input, input_len);
        if (use_u64) hash64 = (uint64_t)hash32;
    }
    else if (strcmp(algorithm, "crc64") == 0) {
        hash64 = crc64(input, input_len);
        if (!use_u64) hash32 = (uint32_t)hash64;
    }
    else if (strcmp(algorithm, "fnv32") == 0) {
        hash32 = fnv32(input, input_len);
        if (use_u64) hash64 = (uint64_t)hash32;
    }
    else if (strcmp(algorithm, "fnv64") == 0) {
        hash64 = fnv64(input, input_len);
        if (!use_u64) hash32 = (uint32_t)hash64;
    }
    else if (strcmp(algorithm, "djb2") == 0) {
        hash32 = djb2(input, input_len);
        if (use_u64) hash64 = (uint64_t)hash32;
    }
    else if (strcmp(algorithm, "sdbm") == 0) {
        hash32 = sdbm(input, input_len);
        if (use_u64) hash64 = (uint64_t)hash32;
    }
    else if (strcmp(algorithm, "xor") == 0) {
        hash32 = xor_hash(input, input_len);
        if (use_u64) hash64 = (uint64_t)hash32;
    }
    // Advanced hash functions
    else if (strcmp(algorithm, "murmur3_32") == 0) {
        hash32 = murmur3_32(input, input_len, 0);
        if (use_u64) hash64 = (uint64_t)hash32;
    }
    else if (strcmp(algorithm, "murmur3_64") == 0) {
        hash64 = murmur3_64(input, input_len, 0);
        if (!use_u64) hash32 = (uint32_t)hash64;
    }
    else if (strcmp(algorithm, "cityhash32") == 0) {
        hash32 = cityhash32(input, input_len);
        if (use_u64) hash64 = (uint64_t)hash32;
    }
    else if (strcmp(algorithm, "cityhash64") == 0) {
        hash64 = cityhash64(input, input_len);
        if (!use_u64) hash32 = (uint32_t)hash64;
    }
    else if (strcmp(algorithm, "xxhash32") == 0) {
        hash32 = xxhash32(input, input_len, 0);
        if (use_u64) hash64 = (uint64_t)hash32;
    }
    else if (strcmp(algorithm, "xxhash64") == 0) {
        hash64 = xxhash64(input, input_len, 0);
        if (!use_u64) hash32 = (uint32_t)hash64;
    }
    else {
        return -3; // unknown algorithm
    }

    // ===================================================
    // Select Output Base
    // ===================================================
    if (strcmp(base, "hex") == 0 || strcmp(base, "auto") == 0) {
        if (use_u64) u64_to_hex(hash64, output, output_len);
        else u32_to_hex(hash32, output, output_len);
    } else if (strcmp(base, "dec") == 0) {
        if (use_u64) u64_to_dec(hash64, output, output_len);
        else u32_to_dec(hash32, output, output_len);
    } else if (strcmp(base, "oct") == 0) {
        if (use_u64) u64_to_oct(hash64, output, output_len);
        else u32_to_oct(hash32, output, output_len);
    } else if (strcmp(base, "bin") == 0) {
        if (use_u64) u64_to_bin(hash64, output, output_len);
        else u32_to_bin(hash32, output, output_len);
    } else {
        return -4; // unsupported base
    }

    return 0;
}
