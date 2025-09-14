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
#include "fossil/cryptic/hash.h"
#include <string.h> /* for memcpy if needed */

/* ---------------------------
 * SHA-256
 * -------------------------*/
#define ROTR(x,n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTR(x,2) ^ ROTR(x,13) ^ ROTR(x,22))
#define EP1(x) (ROTR(x,6) ^ ROTR(x,11) ^ ROTR(x,25))
#define SIG0(x) (ROTR(x,7) ^ ROTR(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTR(x,17) ^ ROTR(x,19) ^ ((x) >> 10))

static const uint32_t fossil_sha256_k[64] = {
    0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,
    0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
    0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,
    0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
    0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,
    0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
    0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,
    0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
    0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,
    0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
    0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,
    0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
    0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,
    0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
    0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,
    0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u
};

static void fossil_sha256_transform(fossil_cryptic_hash_sha256_ctx_t *ctx, const uint8_t data[64]) {
    uint32_t m[64];
    uint32_t a,b,c,d,e,f,g,h;
    int i;

    for (i = 0; i < 16; ++i) {
        m[i]  = (uint32_t)data[i * 4] << 24;
        m[i] |= (uint32_t)data[i * 4 + 1] << 16;
        m[i] |= (uint32_t)data[i * 4 + 2] << 8;
        m[i] |= (uint32_t)data[i * 4 + 3];
    }
    for (i = 16; i < 64; ++i) {
        m[i] = SIG1(m[i-2]) + m[i-7] + SIG0(m[i-15]) + m[i-16];
    }

    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];

    for (i = 0; i < 64; ++i) {
        uint32_t t1 = h + EP1(e) + CH(e,f,g) + fossil_sha256_k[i] + m[i];
        uint32_t t2 = EP0(a) + MAJ(a,b,c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

void fossil_cryptic_hash_sha256_init(fossil_cryptic_hash_sha256_ctx_t *ctx) {
    ctx->bitlen = 0;
    ctx->state[0] = 0x6a09e667u;
    ctx->state[1] = 0xbb67ae85u;
    ctx->state[2] = 0x3c6ef372u;
    ctx->state[3] = 0xa54ff53au;
    ctx->state[4] = 0x510e527fu;
    ctx->state[5] = 0x9b05688cu;
    ctx->state[6] = 0x1f83d9abu;
    ctx->state[7] = 0x5be0cd19u;
}

void fossil_cryptic_hash_sha256_update(fossil_cryptic_hash_sha256_ctx_t *ctx, const void *data, size_t len) {
    size_t i;
    const uint8_t *d = (const uint8_t*)data;
    size_t idx = (size_t)((ctx->bitlen / 8) % 64);

    ctx->bitlen += (uint64_t)len * 8;

    for (i = 0; i < len; ++i) {
        ctx->buffer[idx++] = d[i];
        if (idx == 64) {
            fossil_sha256_transform(ctx, ctx->buffer);
            idx = 0;
        }
    }
}

void fossil_cryptic_hash_sha256_final(fossil_cryptic_hash_sha256_ctx_t *ctx, uint8_t out[32]) {
    size_t idx = (size_t)((ctx->bitlen / 8) % 64);
    size_t padlen = (idx < 56) ? (56 - idx) : (120 - idx);
    uint8_t pad[128] = {0x80};

    /* Append padding and length */
    uint64_t bitlen_be = ((ctx->bitlen & 0xFF00000000000000ULL) >> 56) |
                         ((ctx->bitlen & 0x00FF000000000000ULL) >> 40) |
                         ((ctx->bitlen & 0x0000FF0000000000ULL) >> 24) |
                         ((ctx->bitlen & 0x000000FF00000000ULL) >> 8)  |
                         ((ctx->bitlen & 0x00000000FF000000ULL) << 8)  |
                         ((ctx->bitlen & 0x0000000000FF0000ULL) << 24) |
                         ((ctx->bitlen & 0x000000000000FF00ULL) << 40) |
                         ((ctx->bitlen & 0x00000000000000FFULL) << 56);

    fossil_cryptic_hash_sha256_update(ctx, pad, padlen);
    fossil_cryptic_hash_sha256_update(ctx, &bitlen_be, 8);

    for (int i = 0; i < 8; ++i) {
        out[i*4]     = (uint8_t)(ctx->state[i] >> 24);
        out[i*4 + 1] = (uint8_t)(ctx->state[i] >> 16);
        out[i*4 + 2] = (uint8_t)(ctx->state[i] >> 8);
        out[i*4 + 3] = (uint8_t)(ctx->state[i]);
    }
}

void fossil_cryptic_hash_sha256(const void *data, size_t len, uint8_t out[32]) {
    fossil_cryptic_hash_sha256_ctx_t ctx;
    fossil_cryptic_hash_sha256_init(&ctx);
    fossil_cryptic_hash_sha256_update(&ctx, data, len);
    fossil_cryptic_hash_sha256_final(&ctx, out);
}

void fossil_cryptic_hash_sha256_to_hex(const uint8_t hash[32], char dest[65]) {
    static const char hexchars[] = "0123456789abcdef";
    for (int i = 0; i < 32; ++i) {
        dest[i*2]     = hexchars[(hash[i] >> 4) & 0xF];
        dest[i*2 + 1] = hexchars[hash[i] & 0xF];
    }
    dest[64] = '\0';
}

/* ---------------------------
 * CRC32 (IEEE 802.3)
 * -------------------------*/

/* Table and lazy init flag */
static uint32_t fossil_crc32_table[256];
static int      fossil_crc32_table_inited = 0;

static void fossil_crc32_init_table(void) {
    if (fossil_crc32_table_inited) return;
    const uint32_t poly = 0xEDB88320u;
    for (uint32_t i = 0; i < 256; ++i) {
        uint32_t crc = i;
        for (int j = 0; j < 8; ++j) {
            if (crc & 1) crc = (crc >> 1) ^ poly;
            else crc = crc >> 1;
        }
        fossil_crc32_table[i] = crc;
    }
    fossil_crc32_table_inited = 1;
}

uint32_t fossil_cryptic_hash_crc32(const void *data, size_t len) {
    fossil_crc32_init_table();
    const unsigned char *p = (const unsigned char*)data;
    uint32_t crc = 0xFFFFFFFFu;
    while (len--) {
        crc = (crc >> 8) ^ fossil_crc32_table[(crc ^ *p++) & 0xFFu];
    }
    return crc ^ 0xFFFFFFFFu;
}

/* ---------------------------
 * FNV-1a 32-bit and 64-bit
 * -------------------------*/

uint32_t fossil_cryptic_hash_fnv1a32(const void *data, size_t len) {
    const unsigned char *p = (const unsigned char*)data;
    uint32_t h = 0x811C9DC5u; /* offset basis */
    const uint32_t prime = 0x01000193u;
    for (size_t i = 0; i < len; ++i) {
        h ^= (uint32_t)(*p++);
        h *= prime;
    }
    return h;
}

uint64_t fossil_cryptic_hash_fnv1a64(const void *data, size_t len) {
    const unsigned char *p = (const unsigned char*)data;
    uint64_t h = 0xcbf29ce484222325ULL; /* offset basis */
    const uint64_t prime = 0x100000001B3ULL;
    for (size_t i = 0; i < len; ++i) {
        h ^= (uint64_t)(*p++);
        h *= prime;
    }
    return h;
}

/* ---------------------------
 * MurmurHash3 x86_32
 * (single-shot reference-style)
 * -------------------------*/

uint32_t fossil_cryptic_hash_murmur3_32(const void *key, size_t len, uint32_t seed) {
    const uint8_t *data = (const uint8_t *)key;
    const int nblocks = (int)(len / 4);
    uint32_t h1 = seed;

    const uint32_t c1 = 0xcc9e2d51u;
    const uint32_t c2 = 0x1b873593u;

    /* body */
    const uint32_t *blocks = (const uint32_t *)(data + nblocks*4);
    for (int i = -nblocks; i; i++) {
        uint32_t k1 = blocks[i];
        k1 *= c1;
        k1 = (k1 << 15) | (k1 >> (32 - 15));
        k1 *= c2;

        h1 ^= k1;
        h1 = (h1 << 13) | (h1 >> (32 - 13));
        h1 = h1*5 + 0xe6546b64u;
    }

    /* tail */
    const uint8_t *tail = (const uint8_t*)(data + nblocks*4);
    uint32_t k1 = 0;
    switch (len & 3) {
        case 3: k1 ^= ((uint32_t)tail[2]) << 16; /* fallthrough */
        case 2: k1 ^= ((uint32_t)tail[1]) << 8;  /* fallthrough */
        case 1:
            k1 ^= ((uint32_t)tail[0]);
            k1 *= c1;
            k1 = (k1 << 15) | (k1 >> (32 - 15));
            k1 *= c2;
            h1 ^= k1;
    }

    /* finalization */
    h1 ^= (uint32_t)len;
    /* fmix32 */
    h1 ^= h1 >> 16;
    h1 *= 0x85ebca6bu;
    h1 ^= h1 >> 13;
    h1 *= 0xc2b2ae35u;
    h1 ^= h1 >> 16;

    return h1;
}

/* ---------------------------
 * Streaming API
 * -------------------------*/

void fossil_cryptic_hash_init(fossil_cryptic_hash_ctx_t *ctx, fossil_cryptic_hash_alg_t alg) {
    if (!ctx) return;
    ctx->alg = alg;
    switch (alg) {
        case FOSSIL_CRYPTIC_HASH_ALG_CRC32:
            fossil_crc32_init_table();
            ctx->state.crc32 = 0xFFFFFFFFu;
            break;
        case FOSSIL_CRYPTIC_HASH_ALG_FNV1A32:
            ctx->state.fnv1a32 = 0x811C9DC5u;
            break;
        case FOSSIL_CRYPTIC_HASH_ALG_FNV1A64:
            ctx->state.fnv1a64 = 0xcbf29ce484222325ULL;
            break;
        case FOSSIL_CRYPTIC_HASH_ALG_SHA256:
            fossil_cryptic_hash_sha256_init(&ctx->state.sha256);
            break;
        default:
            ctx->state.crc32 = 0;
            break;
    }
}

void fossil_cryptic_hash_update(fossil_cryptic_hash_ctx_t *ctx, const void *data, size_t len) {
    if (!ctx || !data || len == 0) return;
    const unsigned char *p = (const unsigned char*)data;
    switch (ctx->alg) {
        case FOSSIL_CRYPTIC_HASH_ALG_CRC32: {
            uint32_t crc = ctx->state.crc32;
            while (len--) {
                crc = (crc >> 8) ^ fossil_crc32_table[(crc ^ *p++) & 0xFFu];
            }
            ctx->state.crc32 = crc;
            break;
        }
        case FOSSIL_CRYPTIC_HASH_ALG_FNV1A32: {
            uint32_t h = ctx->state.fnv1a32;
            const uint32_t prime = 0x01000193u;
            while (len--) {
                h ^= (uint32_t)(*p++);
                h *= prime;
            }
            ctx->state.fnv1a32 = h;
            break;
        }
        case FOSSIL_CRYPTIC_HASH_ALG_FNV1A64: {
            uint64_t h = ctx->state.fnv1a64;
            const uint64_t prime = 0x100000001B3ULL;
            while (len--) {
                h ^= (uint64_t)(*p++);
                h *= prime;
            }
            ctx->state.fnv1a64 = h;
            break;
        }
        case FOSSIL_CRYPTIC_HASH_ALG_SHA256:
            fossil_cryptic_hash_sha256_update(&ctx->state.sha256, data, len);
            break;
        default:
            break;
    }
}

uint32_t fossil_cryptic_hash_final32(fossil_cryptic_hash_ctx_t *ctx) {
    if (!ctx) return 0;
    switch (ctx->alg) {
        case FOSSIL_CRYPTIC_HASH_ALG_CRC32:
            return ctx->state.crc32 ^ 0xFFFFFFFFu;
        case FOSSIL_CRYPTIC_HASH_ALG_FNV1A32:
            return ctx->state.fnv1a32;
        case FOSSIL_CRYPTIC_HASH_ALG_MURMUR3_32:
            /* No streaming support; return 0 */
            return 0;
        default:
            return 0;
    }
}

uint64_t fossil_cryptic_hash_final64(fossil_cryptic_hash_ctx_t *ctx) {
    if (!ctx) return 0;
    if (ctx->alg == FOSSIL_CRYPTIC_HASH_ALG_FNV1A64) {
        return ctx->state.fnv1a64;
    }
    /* other algs don't provide 64-bit final */
    return 0;
}

void fossil_cryptic_hash_final_sha256(fossil_cryptic_hash_ctx_t *ctx, uint8_t out[32]) {
    if (!ctx || ctx->alg != FOSSIL_CRYPTIC_HASH_ALG_SHA256) {
        memset(out, 0, 32);
        return;
    }
    fossil_cryptic_hash_sha256_final(&ctx->state.sha256, out);
}

/* ---------------------------
 * Hex helpers
 * -------------------------*/

void fossil_cryptic_hash_u32_to_hex(uint32_t h, char dest[9]) {
    static const char hexchars[] = "0123456789abcdef";
    for (int i = 0; i < 8; ++i) {
        dest[7 - i] = hexchars[(h >> (i * 4)) & 0xFu];
    }
    dest[8] = '\0';
}

void fossil_cryptic_hash_u64_to_hex(uint64_t h, char dest[17]) {
    static const char hexchars[] = "0123456789abcdef";
    for (int i = 0; i < 16; ++i) {
        dest[15 - i] = hexchars[(h >> (i * 4)) & 0xFu];
    }
    dest[16] = '\0';
}
