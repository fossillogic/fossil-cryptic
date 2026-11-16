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
#include "fossil/cryptic/util.h"
#include <string.h>

/* ============================================================
 * BLAKE2b (from original, cleaned)
 * ============================================================ */

static uint64_t blake2b_rotr64(uint64_t v, unsigned int n) {
    return (v >> n) | (v << (64 - n));
}

static uint64_t blake2b_load64(const uint8_t *p) {
    uint64_t v = 0;
    for (unsigned i = 0; i < 8; i++)
        v |= (uint64_t)p[i] << (8 * i);
    return v;
}

// static void blake2b_store64(uint8_t *p, uint64_t v) {
//     for (unsigned i = 0; i < 8; i++)
//         p[i] = (uint8_t)(v >> (8 * i));
// }

static void blake2b_g(uint64_t *v, int a, int b, int c, int d, uint64_t x, uint64_t y) {
    v[a] = v[a] + v[b] + x;
    v[d] = blake2b_rotr64(v[d] ^ v[a], 32);
    v[c] += v[d];
    v[b] = blake2b_rotr64(v[b] ^ v[c], 24);
    v[a] = v[a] + v[b] + y;
    v[d] = blake2b_rotr64(v[d] ^ v[a], 16);
    v[c] += v[d];
    v[b] = blake2b_rotr64(v[b] ^ v[c], 63);
}

static void blake2b_compress(uint64_t *h, const uint8_t block[128], uint64_t t, int last) {
    static const uint64_t IV[8] = {
        0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
        0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
        0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
        0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
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
    for (int i = 0; i < 16; i++)
        m[i] = blake2b_load64(block + i * 8);

    for (int i = 0; i < 8; i++) {
        v[i]     = h[i];
        v[i + 8] = IV[i];
    }
    v[12] ^= t;
    if (last)
        v[14] = ~v[14];

    for (int r = 0; r < 12; r++) {
        const uint8_t *s = sigma[r];
        blake2b_g(v, 0, 4, 8,12, m[s[ 0]], m[s[ 1]]);
        blake2b_g(v, 1, 5, 9,13, m[s[ 2]], m[s[ 3]]);
        blake2b_g(v, 2, 6,10,14, m[s[ 4]], m[s[ 5]]);
        blake2b_g(v, 3, 7,11,15, m[s[ 6]], m[s[ 7]]);
        blake2b_g(v, 0, 5,10,15, m[s[ 8]], m[s[ 9]]);
        blake2b_g(v, 1, 6,11,12, m[s[10]], m[s[11]]);
        blake2b_g(v, 2, 7, 8,13, m[s[12]], m[s[13]]);
        blake2b_g(v, 3, 4, 9,14, m[s[14]], m[s[15]]);
    }

    for (int i = 0; i < 8; i++)
        h[i] ^= v[i] ^ v[i + 8];
}

static int blake2b_generic(const void *in, size_t in_len, uint8_t *out, size_t out_len) {
    if (!out || out_len == 0 || out_len > 64) return -1;
    if (in_len && !in) return -1;

    static const uint64_t IV[8] = {
        0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
        0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
        0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
        0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
    };

    uint64_t h[8];
    memcpy(h, IV, sizeof(h));
    h[0] ^= 0x01010000ULL ^ (uint64_t)out_len; /* unkeyed, outlen bytes */

    const uint8_t *data = (const uint8_t *)in;
    uint8_t block[128];
    size_t offset = 0;

    while (in_len - offset > 128) {
        blake2b_compress(h, data + offset, (uint64_t)(offset + 128), 0);
        offset += 128;
    }

    size_t rem = in_len - offset;
    memset(block, 0, 128);
    if (rem)
        memcpy(block, data + offset, rem);

    blake2b_compress(h, block, (uint64_t)in_len, 1);

    for (size_t i = 0; i < out_len; i++)
        out[i] = (uint8_t)(h[i / 8] >> (8 * (i % 8)));

    fossil_cryptic_util_wipe(h, sizeof(h));
    fossil_cryptic_util_wipe(block, sizeof(block));
    return 0;
}

int fossil_cryptic_hash_blake2b_512(const void *in, size_t in_len, uint8_t out[64]) {
    return blake2b_generic(in, in_len, out, 64);
}

int fossil_cryptic_hash_blake2b_256(const void *in, size_t in_len, uint8_t out[32]) {
    return blake2b_generic(in, in_len, out, 32);
}

/* ============================================================
 * SHA-256 (clean portable implementation)
 * ============================================================ */

static const uint32_t K256[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

#define ROTR32(x,n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x,y,z)  (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x)     (ROTR32(x,2) ^ ROTR32(x,13) ^ ROTR32(x,22))
#define EP1(x)     (ROTR32(x,6) ^ ROTR32(x,11) ^ ROTR32(x,25))
#define SIG0(x)    (ROTR32(x,7) ^ ROTR32(x,18) ^ ((x) >> 3))
#define SIG1(x)    (ROTR32(x,17) ^ ROTR32(x,19) ^ ((x) >> 10))

static void sha256_transform(uint32_t state[8], const uint8_t block[64]) {
    uint32_t a,b,c,d,e,f,g,h,t1,t2,w[64];

    for (int i = 0; i < 16; i++) {
        w[i] = ((uint32_t)block[i*4] << 24) | ((uint32_t)block[i*4+1] << 16) |
               ((uint32_t)block[i*4+2] <<  8) | (uint32_t)block[i*4+3];
    }
    for (int i = 16; i < 64; i++)
        w[i] = SIG1(w[i-2]) + w[i-7] + SIG0(w[i-15]) + w[i-16];

    a = state[0]; b = state[1]; c = state[2]; d = state[3];
    e = state[4]; f = state[5]; g = state[6]; h = state[7];

    for (int i = 0; i < 64; i++) {
        t1 = h + EP1(e) + CH(e,f,g) + K256[i] + w[i];
        t2 = EP0(a) + MAJ(a,b,c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

int fossil_cryptic_hash_sha256(const void *in, size_t in_len, uint8_t out[32]) {
    if (!out) return -1;
    if (in_len && !in) return -1;

    uint32_t state[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    const uint8_t *data = (const uint8_t *)in;
    uint8_t block[64];
    uint64_t bitlen = (uint64_t)in_len * 8;
    size_t offset = 0;

    while (in_len - offset >= 64) {
        sha256_transform(state, data + offset);
        offset += 64;
    }

    size_t rem = in_len - offset;
    memset(block, 0, 64);
    if (rem) memcpy(block, data + offset, rem);
    block[rem] = 0x80;

    if (rem >= 56) {
        sha256_transform(state, block);
        memset(block, 0, 64);
    }

    /* append length in bits (big-endian) */
    for (int i = 0; i < 8; i++)
        block[63 - i] = (uint8_t)(bitlen >> (8 * i));

    sha256_transform(state, block);

    for (int i = 0; i < 8; i++) {
        out[i*4    ] = (uint8_t)(state[i] >> 24);
        out[i*4 + 1] = (uint8_t)(state[i] >> 16);
        out[i*4 + 2] = (uint8_t)(state[i] >>  8);
        out[i*4 + 3] = (uint8_t)(state[i]);
    }

    fossil_cryptic_util_wipe(state, sizeof(state));
    fossil_cryptic_util_wipe(block, sizeof(block));
    return 0;
}

/* SHA-512 can be added later following the same pattern */

int fossil_cryptic_hash_sha512(const void *in, size_t in_len, uint8_t out[64]) {
    (void)in; (void)in_len; (void)out;
    return -1; /* placeholder – implement when needed */
}

/* ============================================================
 * Non-cryptographic hashes
 * ============================================================ */

uint32_t fossil_cryptic_hash_crc32(const void *in, size_t in_len) {
    const uint8_t *p = (const uint8_t *)in;
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < in_len; i++) {
        crc ^= p[i];
        for (int j = 0; j < 8; j++)
            crc = (crc >> 1) ^ (0xEDB88320u & -(crc & 1u));
    }
    return ~crc;
}

uint64_t fossil_cryptic_hash_crc64(const void *in, size_t in_len) {
    const uint8_t *p = (const uint8_t *)in;
    uint64_t crc = 0xFFFFFFFFFFFFFFFFull;
    for (size_t i = 0; i < in_len; i++) {
        crc ^= p[i];
        for (int j = 0; j < 8; j++)
            crc = (crc >> 1) ^ (0xC96C5795D7870F42ull & -(int64_t)(crc & 1));
    }
    return ~crc;
}

uint32_t fossil_cryptic_hash_fnv32(const void *in, size_t in_len) {
    const uint8_t *p = (const uint8_t *)in;
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < in_len; i++) {
        h ^= p[i];
        h *= 16777619u;
    }
    return h;
}

uint64_t fossil_cryptic_hash_fnv64(const void *in, size_t in_len) {
    const uint8_t *p = (const uint8_t *)in;
    uint64_t h = 14695981039346656037ull;
    for (size_t i = 0; i < in_len; i++) {
        h ^= p[i];
        h *= 1099511628211ull;
    }
    return h;
}

uint32_t fossil_cryptic_hash_djb2(const void *in, size_t in_len) {
    const uint8_t *p = (const uint8_t *)in;
    uint32_t h = 5381u;
    for (size_t i = 0; i < in_len; i++)
        h = ((h << 5) + h) + p[i];
    return h;
}

uint32_t fossil_cryptic_hash_sdbm(const void *in, size_t in_len) {
    const uint8_t *p = (const uint8_t *)in;
    uint32_t h = 0;
    for (size_t i = 0; i < in_len; i++)
        h = p[i] + (h << 6) + (h << 16) - h;
    return h;
}
