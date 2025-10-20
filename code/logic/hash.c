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
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

#if defined(_WIN32)
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#  include <process.h>
#elif defined(__APPLE__)
#  include <mach/mach.h>
#  include <mach/thread_act.h>
#  include <mach/thread_policy.h>
#  include <pthread.h>
#  include <sched.h>
#  include <time.h>
#  include <unistd.h>
#  include <sys/types.h>
#else
#  define _GNU_SOURCE
#  include <pthread.h>
#  include <sched.h>
#  include <time.h>
#  include <unistd.h>
#  include <sys/types.h>
#endif

/* ------------------------ helpers ------------------------ */

static int strcaseeq(const char *a, const char *b) {
    if (!a || !b) return 0;
    while (*a && *b) {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) return 0;
        a++; b++;
    }
    return *a == *b;
}

/* hex encode: out must have at least (nbytes*2 + 1) bytes */
static void hex_encode_lower(const uint8_t *in, size_t n, char *out) {
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < n; ++i) {
        out[i*2 + 0] = hex[(in[i] >> 4) & 0xF];
        out[i*2 + 1] = hex[in[i] & 0xF];
    }
    out[n*2] = '\0';
}

/* base62 encode: out must have at least (ceil(n*8/6) + 1) bytes */
static const char b62chars[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
static int base62_encode(const uint8_t *in, size_t inlen, char *out, size_t outlen) {
    /* base62 encoding: treat input as a big integer, convert to base62 */
    /* This is not a standard, but a simple implementation for hash output */
    uint8_t buf[64];
    size_t buflen = inlen;
    if (buflen > sizeof(buf)) return -1;
    memcpy(buf, in, buflen);
    size_t outpos = 0;
    while (buflen > 0 && outpos + 1 < outlen) {
        uint32_t rem = 0;
        for (size_t i = 0; i < buflen; ++i) {
            uint32_t val = (rem << 8) | buf[i];
            buf[i] = (uint8_t)(val / 62);
            rem = val % 62;
        }
        out[outpos++] = b62chars[rem];
        /* remove leading zeros */
        size_t leading = 0;
        while (leading < buflen && buf[leading] == 0) leading++;
        if (leading) {
            memmove(buf, buf + leading, buflen - leading);
            buflen -= leading;
        }
    }
    if (outpos >= outlen) return -1;
    out[outpos] = '\0';
    /* reverse output */
    for (size_t i = 0; i < outpos/2; ++i) {
        char t = out[i];
        out[i] = out[outpos-1-i];
        out[outpos-1-i] = t;
    }
    return 0;
}

/* base36 encode: similar to base62, but using 0-9A-Z */
static const char b36chars[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
static int base36_encode(const uint8_t *in, size_t inlen, char *out, size_t outlen) {
    uint8_t buf[64];
    size_t buflen = inlen;
    if (buflen > sizeof(buf)) return -1;
    memcpy(buf, in, buflen);
    size_t outpos = 0;
    while (buflen > 0 && outpos + 1 < outlen) {
        uint32_t rem = 0;
        for (size_t i = 0; i < buflen; ++i) {
            uint32_t val = (rem << 8) | buf[i];
            buf[i] = (uint8_t)(val / 36);
            rem = val % 36;
        }
        out[outpos++] = b36chars[rem];
        size_t leading = 0;
        while (leading < buflen && buf[leading] == 0) leading++;
        if (leading) {
            memmove(buf, buf + leading, buflen - leading);
            buflen -= leading;
        }
    }
    if (outpos >= outlen) return -1;
    out[outpos] = '\0';
    for (size_t i = 0; i < outpos/2; ++i) {
        char t = out[i];
        out[i] = out[outpos-1-i];
        out[outpos-1-i] = t;
    }
    return 0;
}

/* simple base64 encoder (RFC 4648, with padding '=') */
static const char b64chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static int base64_encode(const uint8_t *in, size_t inlen, char *out, size_t outlen) {
    size_t needed = ((inlen + 2) / 3) * 4 + 1;
    if (outlen < needed) return -1;
    size_t i = 0, o = 0;
    while (i + 2 < inlen) {
        uint32_t triple = (in[i] << 16) | (in[i+1] << 8) | in[i+2];
        out[o++] = b64chars[(triple >> 18) & 0x3F];
        out[o++] = b64chars[(triple >> 12) & 0x3F];
        out[o++] = b64chars[(triple >> 6)  & 0x3F];
        out[o++] = b64chars[(triple)       & 0x3F];
        i += 3;
    }
    if (i < inlen) {
        uint8_t a = in[i++];
        uint8_t b = (i < inlen) ? in[i++] : 0;
        uint32_t triple = (a << 16) | (b << 8);
        out[o++] = b64chars[(triple >> 18) & 0x3F];
        out[o++] = b64chars[(triple >> 12) & 0x3F];
        if (i <= inlen) out[o++] = (i == (inlen+1)) ? '=' : b64chars[(triple >> 6) & 0x3F];
        else out[o++] = '=';
        out[o++] = '=';
    }
    out[o] = '\0';
    return 0;
}

/* write a 32-bit result into a byte buffer (big-endian) */
static void u32_to_be(uint32_t v, uint8_t *out) {
    out[0] = (uint8_t)(v >> 24);
    out[1] = (uint8_t)(v >> 16);
    out[2] = (uint8_t)(v >> 8);
    out[3] = (uint8_t)(v);
}

/* write a 64-bit result into a byte buffer (big-endian) */
static void u64_to_be(uint64_t v, uint8_t *out) {
    for (int i = 0; i < 8; ++i) {
        out[7 - i] = (uint8_t)(v & 0xFF);
        v >>= 8;
    }
}

/* ------------------------ hash implementations ------------------------ */

/* FNV-1a 32-bit */
static uint32_t fnv1a_32(const void *data, size_t len) {
    const uint8_t *p = (const uint8_t*)data;
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < len; ++i) {
        h ^= p[i];
        h *= 16777619u;
    }
    return h;
}

/* FNV-1a 64-bit */
static uint64_t fnv1a_64(const void *data, size_t len) {
    const uint8_t *p = (const uint8_t*)data;
    uint64_t h = 14695981039346656037ULL;
    for (size_t i = 0; i < len; ++i) {
        h ^= p[i];
        h *= 1099511628211ULL;
    }
    return h;
}

/* CRC32 (IEEE 802.3) - compute table on first call */
static uint32_t crc32_table[256];
static int crc32_table_inited = 0;
static void crc32_init_table(void) {
    uint32_t poly = 0xEDB88320u;
    for (uint32_t i = 0; i < 256; ++i) {
        uint32_t crc = i;
        for (int j = 0; j < 8; ++j) {
            if (crc & 1) crc = (crc >> 1) ^ poly;
            else crc >>= 1;
        }
        crc32_table[i] = crc;
    }
    crc32_table_inited = 1;
}
static uint32_t crc32(const void *data, size_t len) {
    if (!crc32_table_inited) crc32_init_table();
    const uint8_t *p = (const uint8_t*)data;
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; ++i) {
        uint8_t idx = (uint8_t)((crc ^ p[i]) & 0xFF);
        crc = (crc >> 8) ^ crc32_table[idx];
    }
    return crc ^ 0xFFFFFFFFu;
}

/* MurmurHash3 x86_32 (public domain original by Austin Appleby) */
static uint32_t murmur3_32(const void *key, size_t len, uint32_t seed) {
    const uint8_t *data = (const uint8_t*)key;
    const int nblocks = (int)(len / 4);
    uint32_t h1 = seed;

    const uint32_t c1 = 0xcc9e2d51;
    const uint32_t c2 = 0x1b873593;

    const uint32_t *blocks = (const uint32_t *)(data + nblocks*4);
    for (int i = -nblocks; i; ++i) {
        uint32_t k1 = blocks[i];
        k1 *= c1;
        k1 = (k1 << 15) | (k1 >> (32 - 15));
        k1 *= c2;

        h1 ^= k1;
        h1 = (h1 << 13) | (h1 >> (32 - 13));
        h1 = h1*5 + 0xe6546b64;
    }

    const uint8_t *tail = data + nblocks*4;
    uint32_t k1 = 0;
    switch (len & 3) {
      case 3: k1 ^= (uint32_t)tail[2] << 16;
      case 2: k1 ^= (uint32_t)tail[1] << 8;
      case 1: k1 ^= (uint32_t)tail[0];
              k1 *= c1; k1 = (k1 << 15) | (k1 >> (32 - 15)); k1 *= c2; h1 ^= k1;
    }

    h1 ^= (uint32_t)len;
    /* fmix32 */
    h1 ^= h1 >> 16;
    h1 *= 0x85ebca6b;
    h1 ^= h1 >> 13;
    h1 *= 0xc2b2ae35;
    h1 ^= h1 >> 16;
    return h1;
}

/* Jenkins one-at-a-time (32-bit) */
static uint32_t jenkins_one_at_a_time(const void *key, size_t len) {
    const uint8_t *p = (const uint8_t*)key;
    uint32_t hash = 0;
    for (size_t i = 0; i < len; ++i) {
        hash += p[i];
        hash += (hash << 10);
        hash ^= (hash >> 6);
    }
    hash += (hash << 3);
    hash ^= (hash >> 11);
    hash += (hash << 15);
    return hash;
}

/* ------------------------ SHA-1, SHA-256, SHA-512 implementations ------------------------ */
/* These are minimal, public domain/CC0 implementations, not optimized for speed. */

/* ---- SHA-1 ---- */
typedef struct {
    uint32_t h[5];
    uint64_t len;
    uint8_t buf[64];
    size_t bufused;
} sha1_ctx;

static void sha1_init(sha1_ctx *ctx) {
    ctx->h[0] = 0x67452301u;
    ctx->h[1] = 0xEFCDAB89u;
    ctx->h[2] = 0x98BADCFEu;
    ctx->h[3] = 0x10325476u;
    ctx->h[4] = 0xC3D2E1F0u;
    ctx->len = 0;
    ctx->bufused = 0;
}

static void sha1_process_block(sha1_ctx *ctx, const uint8_t *block) {
    uint32_t w[80];
    for (int i = 0; i < 16; ++i) {
        w[i] = ((uint32_t)block[i*4+0] << 24) |
               ((uint32_t)block[i*4+1] << 16) |
               ((uint32_t)block[i*4+2] << 8) |
               ((uint32_t)block[i*4+3]);
    }
    for (int i = 16; i < 80; ++i) {
        uint32_t t = w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16];
        w[i] = (t << 1) | (t >> 31);
    }
    uint32_t a = ctx->h[0], b = ctx->h[1], c = ctx->h[2], d = ctx->h[3], e = ctx->h[4];
    for (int i = 0; i < 80; ++i) {
        uint32_t f, k;
        if (i < 20) { f = (b & c) | ((~b) & d); k = 0x5A827999u; }
        else if (i < 40) { f = b ^ c ^ d; k = 0x6ED9EBA1u; }
        else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDCu; }
        else { f = b ^ c ^ d; k = 0xCA62C1D6u; }
        uint32_t temp = ((a << 5) | (a >> 27)) + f + e + k + w[i];
        e = d; d = c; c = (b << 30) | (b >> 2); b = a; a = temp;
    }
    ctx->h[0] += a; ctx->h[1] += b; ctx->h[2] += c; ctx->h[3] += d; ctx->h[4] += e;
}

static void sha1_update(sha1_ctx *ctx, const void *data, size_t len) {
    const uint8_t *p = (const uint8_t*)data;
    ctx->len += len * 8;
    while (len > 0) {
        size_t n = 64 - ctx->bufused;
        if (n > len) n = len;
        memcpy(ctx->buf + ctx->bufused, p, n);
        ctx->bufused += n;
        p += n;
        len -= n;
        if (ctx->bufused == 64) {
            sha1_process_block(ctx, ctx->buf);
            ctx->bufused = 0;
        }
    }
}

static void sha1_final(sha1_ctx *ctx, uint8_t out[20]) {
    size_t i = ctx->bufused;
    ctx->buf[i++] = 0x80;
    if (i > 56) {
        while (i < 64) ctx->buf[i++] = 0;
        sha1_process_block(ctx, ctx->buf);
        i = 0;
    }
    while (i < 56) ctx->buf[i++] = 0;
    uint64_t len_be = ctx->len;
    for (int j = 0; j < 8; ++j)
        ctx->buf[63-j] = (uint8_t)(len_be >> (j*8));
    sha1_process_block(ctx, ctx->buf);
    for (int j = 0; j < 5; ++j) {
        out[j*4+0] = (uint8_t)(ctx->h[j] >> 24);
        out[j*4+1] = (uint8_t)(ctx->h[j] >> 16);
        out[j*4+2] = (uint8_t)(ctx->h[j] >> 8);
        out[j*4+3] = (uint8_t)(ctx->h[j]);
    }
}

static void sha1_hash(const void *data, size_t len, uint8_t out[20]) {
    sha1_ctx ctx;
    sha1_init(&ctx);
    sha1_update(&ctx, data, len);
    sha1_final(&ctx, out);
}

/* ---- SHA-256 ---- */
typedef struct {
    uint32_t h[8];
    uint64_t len;
    uint8_t buf[64];
    size_t bufused;
} sha256_ctx;

static const uint32_t sha256_k[64] = {
    0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
    0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
    0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
    0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
    0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
    0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
    0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
    0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u
};

static void sha256_init(sha256_ctx *ctx) {
    ctx->h[0]=0x6a09e667u; ctx->h[1]=0xbb67ae85u; ctx->h[2]=0x3c6ef372u; ctx->h[3]=0xa54ff53au;
    ctx->h[4]=0x510e527fu; ctx->h[5]=0x9b05688cu; ctx->h[6]=0x1f83d9abu; ctx->h[7]=0x5be0cd19u;
    ctx->len = 0;
    ctx->bufused = 0;
}

static void sha256_process_block(sha256_ctx *ctx, const uint8_t *block) {
    uint32_t w[64];
    for (int i = 0; i < 16; ++i) {
        w[i] = ((uint32_t)block[i*4+0] << 24) |
               ((uint32_t)block[i*4+1] << 16) |
               ((uint32_t)block[i*4+2] << 8) |
               ((uint32_t)block[i*4+3]);
    }
    for (int i = 16; i < 64; ++i) {
        uint32_t s0 = (w[i-15] >> 7 | w[i-15] << (32-7)) ^ (w[i-15] >> 18 | w[i-15] << (32-18)) ^ (w[i-15] >> 3);
        uint32_t s1 = (w[i-2] >> 17 | w[i-2] << (32-17)) ^ (w[i-2] >> 19 | w[i-2] << (32-19)) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    uint32_t a=ctx->h[0],b=ctx->h[1],c=ctx->h[2],d=ctx->h[3],e=ctx->h[4],f=ctx->h[5],g=ctx->h[6],h=ctx->h[7];
    for (int i = 0; i < 64; ++i) {
        uint32_t S1 = (e>>6|e<<(32-6)) ^ (e>>11|e<<(32-11)) ^ (e>>25|e<<(32-25));
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t temp1 = h + S1 + ch + sha256_k[i] + w[i];
        uint32_t S0 = (a>>2|a<<(32-2)) ^ (a>>13|a<<(32-13)) ^ (a>>22|a<<(32-22));
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = S0 + maj;
        h = g; g = f; f = e; e = d + temp1;
        d = c; c = b; b = a; a = temp1 + temp2;
    }
    ctx->h[0] += a; ctx->h[1] += b; ctx->h[2] += c; ctx->h[3] += d;
    ctx->h[4] += e; ctx->h[5] += f; ctx->h[6] += g; ctx->h[7] += h;
}

static void sha256_update(sha256_ctx *ctx, const void *data, size_t len) {
    const uint8_t *p = (const uint8_t*)data;
    ctx->len += len * 8;
    while (len > 0) {
        size_t n = 64 - ctx->bufused;
        if (n > len) n = len;
        memcpy(ctx->buf + ctx->bufused, p, n);
        ctx->bufused += n;
        p += n;
        len -= n;
        if (ctx->bufused == 64) {
            sha256_process_block(ctx, ctx->buf);
            ctx->bufused = 0;
        }
    }
}

static void sha256_final(sha256_ctx *ctx, uint8_t out[32]) {
    size_t i = ctx->bufused;
    ctx->buf[i++] = 0x80;
    if (i > 56) {
        while (i < 64) ctx->buf[i++] = 0;
        sha256_process_block(ctx, ctx->buf);
        i = 0;
    }
    while (i < 56) ctx->buf[i++] = 0;
    uint64_t len_be = ctx->len;
    for (int j = 0; j < 8; ++j)
        ctx->buf[63-j] = (uint8_t)(len_be >> (j*8));
    sha256_process_block(ctx, ctx->buf);
    for (int j = 0; j < 8; ++j) {
        out[j*4+0] = (uint8_t)(ctx->h[j] >> 24);
        out[j*4+1] = (uint8_t)(ctx->h[j] >> 16);
        out[j*4+2] = (uint8_t)(ctx->h[j] >> 8);
        out[j*4+3] = (uint8_t)(ctx->h[j]);
    }
}

static void sha256_hash(const void *data, size_t len, uint8_t out[32]) {
    sha256_ctx ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, data, len);
    sha256_final(&ctx, out);
}

/* ---- SHA-512 ---- */
typedef struct {
    uint64_t h[8];
    uint64_t len;
    uint8_t buf[128];
    size_t bufused;
} sha512_ctx;

static const uint64_t sha512_k[80] = {
    0x428a2f98d728ae22ULL,0x7137449123ef65cdULL,0xb5c0fbcfec4d3b2fULL,0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL,0x59f111f1b605d019ULL,0x923f82a4af194f9bULL,0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL,0x12835b0145706fbeULL,0x243185be4ee4b28cULL,0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL,0x80deb1fe3b1696b1ULL,0x9bdc06a725c71235ULL,0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL,0xefbe4786384f25e3ULL,0x0fc19dc68b8cd5b5ULL,0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL,0x4a7484aa6ea6e483ULL,0x5cb0a9dcbd41fbd4ULL,0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL,0xa831c66d2db43210ULL,0xb00327c898fb213fULL,0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL,0xd5a79147930aa725ULL,0x06ca6351e003826fULL,0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL,0x2e1b21385c26c926ULL,0x4d2c6dfc5ac42aedULL,0x53380d139d95b3dfULL,
    0x650a73548baf63deULL,0x766a0abb3c77b2a8ULL,0x81c2c92e47edaee6ULL,0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL,0xa81a664bbc423001ULL,0xc24b8b70d0f89791ULL,0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL,0xd69906245565a910ULL,0xf40e35855771202aULL,0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL,0x1e376c085141ab53ULL,0x2748774cdf8eeb99ULL,0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL,0x4ed8aa4ae3418acbULL,0x5b9cca4f7763e373ULL,0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL,0x78a5636f43172f60ULL,0x84c87814a1f0ab72ULL,0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL,0xa4506cebde82bde9ULL,0xbef9a3f7b2c67915ULL,0xc67178f2e372532bULL,
    0xca273eceea26619cULL,0xd186b8c721c0c207ULL,0xeada7dd6cde0eb1eULL,0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL,0x0a637dc5a2c898a6ULL,0x113f9804bef90daeULL,0x1b710b35131c471bULL,
    0x28db77f523047d84ULL,0x32caab7b40c72493ULL,0x3c9ebe0a15c9bebcULL,0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL,0x597f299cfc657e2aULL,0x5fcb6fab3ad6faecULL,0x6c44198c4a475817ULL
};

static void sha512_init(sha512_ctx *ctx) {
    ctx->h[0]=0x6a09e667f3bcc908ULL; ctx->h[1]=0xbb67ae8584caa73bULL;
    ctx->h[2]=0x3c6ef372fe94f82bULL; ctx->h[3]=0xa54ff53a5f1d36f1ULL;
    ctx->h[4]=0x510e527fade682d1ULL; ctx->h[5]=0x9b05688c2b3e6c1fULL;
    ctx->h[6]=0x1f83d9abfb41bd6bULL; ctx->h[7]=0x5be0cd19137e2179ULL;
    ctx->len = 0;
    ctx->bufused = 0;
}

static void sha512_process_block(sha512_ctx *ctx, const uint8_t *block) {
    uint64_t w[80];
    for (int i = 0; i < 16; ++i) {
        w[i] = ((uint64_t)block[i*8+0] << 56) |
               ((uint64_t)block[i*8+1] << 48) |
               ((uint64_t)block[i*8+2] << 40) |
               ((uint64_t)block[i*8+3] << 32) |
               ((uint64_t)block[i*8+4] << 24) |
               ((uint64_t)block[i*8+5] << 16) |
               ((uint64_t)block[i*8+6] << 8) |
               ((uint64_t)block[i*8+7]);
    }
    for (int i = 16; i < 80; ++i) {
        uint64_t s0 = (w[i-15]>>1|w[i-15]<<(64-1)) ^ (w[i-15]>>8|w[i-15]<<(64-8)) ^ (w[i-15]>>7);
        uint64_t s1 = (w[i-2]>>19|w[i-2]<<(64-19)) ^ (w[i-2]>>61|w[i-2]<<(64-61)) ^ (w[i-2]>>6);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    uint64_t a=ctx->h[0],b=ctx->h[1],c=ctx->h[2],d=ctx->h[3],e=ctx->h[4],f=ctx->h[5],g=ctx->h[6],h=ctx->h[7];
    for (int i = 0; i < 80; ++i) {
        uint64_t S1 = (e>>14|e<<(64-14)) ^ (e>>18|e<<(64-18)) ^ (e>>41|e<<(64-41));
        uint64_t ch = (e & f) ^ ((~e) & g);
        uint64_t temp1 = h + S1 + ch + sha512_k[i] + w[i];
        uint64_t S0 = (a>>28|a<<(64-28)) ^ (a>>34|a<<(64-34)) ^ (a>>39|a<<(64-39));
        uint64_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint64_t temp2 = S0 + maj;
        h = g; g = f; f = e; e = d + temp1;
        d = c; c = b; b = a; a = temp1 + temp2;
    }
    ctx->h[0] += a; ctx->h[1] += b; ctx->h[2] += c; ctx->h[3] += d;
    ctx->h[4] += e; ctx->h[5] += f; ctx->h[6] += g; ctx->h[7] += h;
}

static void sha512_update(sha512_ctx *ctx, const void *data, size_t len) {
    const uint8_t *p = (const uint8_t*)data;
    ctx->len += len * 8;
    while (len > 0) {
        size_t n = 128 - ctx->bufused;
        if (n > len) n = len;
        memcpy(ctx->buf + ctx->bufused, p, n);
        ctx->bufused += n;
        p += n;
        len -= n;
        if (ctx->bufused == 128) {
            sha512_process_block(ctx, ctx->buf);
            ctx->bufused = 0;
        }
    }
}

static void sha512_final(sha512_ctx *ctx, uint8_t out[64]) {
    size_t i = ctx->bufused;
    ctx->buf[i++] = 0x80;
    if (i > 112) {
        while (i < 128) ctx->buf[i++] = 0;
        sha512_process_block(ctx, ctx->buf);
        i = 0;
    }
    while (i < 112) ctx->buf[i++] = 0;
    uint64_t len_be = ctx->len;
    for (int j = 0; j < 16; ++j)
        ctx->buf[127-j] = (uint8_t)(len_be >> (j*8));
    sha512_process_block(ctx, ctx->buf);
    for (int j = 0; j < 8; ++j) {
        out[j*8+0] = (uint8_t)(ctx->h[j] >> 56);
        out[j*8+1] = (uint8_t)(ctx->h[j] >> 48);
        out[j*8+2] = (uint8_t)(ctx->h[j] >> 40);
        out[j*8+3] = (uint8_t)(ctx->h[j] >> 32);
        out[j*8+4] = (uint8_t)(ctx->h[j] >> 24);
        out[j*8+5] = (uint8_t)(ctx->h[j] >> 16);
        out[j*8+6] = (uint8_t)(ctx->h[j] >> 8);
        out[j*8+7] = (uint8_t)(ctx->h[j]);
    }
}

static void sha512_hash(const void *data, size_t len, uint8_t out[64]) {
    sha512_ctx ctx;
    sha512_init(&ctx);
    sha512_update(&ctx, data, len);
    sha512_final(&ctx, out);
}

/* ------------------------ high-level selection ------------------------ */

/* list of supported algorithm ids (lowercase) */
const char *fossil_cryptic_hash_list(void) {
    /* newline separated for easy printing; update when adding new algorithm */
    return "fnv1a\nfnv1a64\ncrc32\nmurmur3\njenkins\nsha1\nsha256\nsha512\n";
}

/* Try to map algorithm name to canonical id (lowercase) */
static const char* canonical_alg(const char *alg) {
    if (!alg) return NULL;
    if (strcaseeq(alg, "fnv1a") || strcaseeq(alg, "fnv-1a")) return "fnv1a";
    if (strcaseeq(alg, "fnv1a64") || strcaseeq(alg, "fnv-1a-64") || strcaseeq(alg, "fnv64")) return "fnv1a64";
    if (strcaseeq(alg, "crc32") || strcaseeq(alg, "crc")) return "crc32";
    if (strcaseeq(alg, "murmur3") || strcaseeq(alg, "murmur") || strcaseeq(alg, "murmur3_32")) return "murmur3";
    if (strcaseeq(alg, "jenkins") || strcaseeq(alg, "jenkins_one") || strcaseeq(alg, "jenkins32")) return "jenkins";
    if (strcaseeq(alg, "sha1") || strcaseeq(alg, "sha-1")) return "sha1";
    if (strcaseeq(alg, "sha256") || strcaseeq(alg, "sha-256")) return "sha256";
    if (strcaseeq(alg, "sha512") || strcaseeq(alg, "sha-512")) return "sha512";
    return NULL;
}

/* Determine if algorithm supports native 64-bit output */
static int alg_has_64bit(const char *canid) {
    if (!canid) return 0;
    if (strcaseeq(canid, "fnv1a64")) return 1;
    if (strcaseeq(canid, "sha512")) return 1;
    if (strcaseeq(canid, "sha256")) return 1;
    return 0;
}

/* Compute 32-bit hash by algorithm canonical id */
static uint32_t compute_u32_by_alg(const char *canid, const void *data, size_t len) {
    if (!canid) return 0;
    if (strcaseeq(canid, "fnv1a")) return fnv1a_32(data, len);
    if (strcaseeq(canid, "crc32")) return crc32(data, len);
    if (strcaseeq(canid, "murmur3")) return murmur3_32(data, len, 0x9747b28c);
    if (strcaseeq(canid, "jenkins")) return jenkins_one_at_a_time(data, len);
    if (strcaseeq(canid, "fnv1a64")) {
        uint64_t v = fnv1a_64(data, len);
        return (uint32_t)(v & 0xFFFFFFFFu);
    }
    if (strcaseeq(canid, "sha1")) {
        uint8_t out[20];
        sha1_hash(data, len, out);
        return ((uint32_t)out[0]<<24) | ((uint32_t)out[1]<<16) | ((uint32_t)out[2]<<8) | out[3];
    }
    if (strcaseeq(canid, "sha256")) {
        uint8_t out[32];
        sha256_hash(data, len, out);
        return ((uint32_t)out[0]<<24) | ((uint32_t)out[1]<<16) | ((uint32_t)out[2]<<8) | out[3];
    }
    if (strcaseeq(canid, "sha512")) {
        uint8_t out[64];
        sha512_hash(data, len, out);
        return ((uint32_t)out[0]<<24) | ((uint32_t)out[1]<<16) | ((uint32_t)out[2]<<8) | out[3];
    }
    /* unknown algorithm -> fallback: fnv1a */
    return fnv1a_32(data, len);
}

/* Compute 64-bit hash by algorithm canonical id.
   If algorithm has native 64, use it.
   Otherwise, promote two 32-bit variants to a 64-bit mix. */
static uint64_t compute_u64_by_alg(const char *canid, const void *data, size_t len) {
    if (!canid) return 0;
    if (strcaseeq(canid, "fnv1a64")) return fnv1a_64(data, len);
    if (strcaseeq(canid, "sha1")) {
        uint8_t out[20];
        sha1_hash(data, len, out);
        uint64_t v = 0;
        for (int i = 0; i < 8; ++i) v = (v << 8) | out[i];
        return v;
    }
    if (strcaseeq(canid, "sha256")) {
        uint8_t out[32];
        sha256_hash(data, len, out);
        uint64_t v = 0;
        for (int i = 0; i < 8; ++i) v = (v << 8) | out[i];
        return v;
    }
    if (strcaseeq(canid, "sha512")) {
        uint8_t out[64];
        sha512_hash(data, len, out);
        uint64_t v = 0;
        for (int i = 0; i < 8; ++i) v = (v << 8) | out[i];
        return v;
    }
    /* for non-native 64, combine two 32-bit hashes (simple, deterministic) */
    uint32_t a = compute_u32_by_alg(canid, data, len);
    /* mix with a second hash of the same data but with a tiny salt appended */
    uint8_t *buf = (uint8_t*)malloc(len + 1);
    if (!buf) return ((uint64_t)a) << 32 | (uint64_t)a;
    memcpy(buf, data, len);
    buf[len] = 0xA5; /* salt byte */
    uint32_t b = compute_u32_by_alg(canid, buf, len+1);
    free(buf);
    uint64_t r = ((uint64_t)a << 32) | (uint64_t)b;
    /* mix bits a bit */
    r ^= (r >> 33);
    r *= 0xff51afd7ed558ccdULL;
    r ^= (r >> 33);
    return r;
}

/* ------------------------ public API ------------------------ */

/*
 * uint32_t fossil_cryptic_hash_u32(const void *data, size_t len, const char *alg)
 *
 * Compute a 32-bit hash value for 'data' using algorithm 'alg' (string id).
 * If alg is NULL or not recognized, fallback to "fnv1a".
 * Thread-safe: no static or global state used.
 */
uint32_t fossil_cryptic_hash_u32(const void *data, size_t len, const char *alg) {
    const char *can = canonical_alg(alg ? alg : "fnv1a");
    if (!can) can = "fnv1a";
    return compute_u32_by_alg(can, data, len);
}

/*
 * uint64_t fossil_cryptic_hash_u64(const void *data, size_t len, const char *alg)
 *
 * Compute a 64-bit hash value for 'data' using algorithm 'alg' (string id).
 * If alg has native 64-bit variant it will be used; otherwise we promote/combine.
 * Thread-safe: no static or global state used.
 */
uint64_t fossil_cryptic_hash_u64(const void *data, size_t len, const char *alg) {
    const char *can = canonical_alg(alg ? alg : "fnv1a");
    if (!can) can = "fnv1a";
    return compute_u64_by_alg(can, data, len);
}

/*
 * int fossil_cryptic_hash_to_str(const void *data, size_t len,
 *                                const char *alg, const char *bit_pref,
 *                                const char *base_pref,
 *                                char *out, size_t outlen)
 *
 * Compute a hash and encode to string according to preferences:
 *  - alg: algorithm name (see list)
 *  - bit_pref: "u32", "u64", or "auto"
 *  - base_pref: "hex", "base64", "base62", "base36", or "auto"
 *
 * The textual representation is written into 'out' (null-terminated).
 * Returns 0 on success, non-zero on error (e.g., outlen too small).
 *
 * Notes:
 *  - For "auto" bit_pref: pick 64 if algorithm has 64-bit native support; else use 32.
 *  - For "auto" base_pref: choose "hex".
 *
 * Thread safety: The caller must provide a buffer 'out' that is not shared between threads.
 * This function does not use any static or global state for output.
 */
int fossil_cryptic_hash_to_str(const void *data, size_t len,
                               const char *alg, const char *bit_pref,
                               const char *base_pref,
                               char *out, size_t outlen)
{
    if (!out || outlen == 0) return -1;
    const char *can = canonical_alg(alg ? alg : "fnv1a");
    if (!can) can = "fnv1a";

    int want64 = 0;
    if (!bit_pref || strcaseeq(bit_pref, "auto")) {
        want64 = alg_has_64bit(can);
    } else if (strcaseeq(bit_pref, "u64") || strcaseeq(bit_pref, "64")) {
        want64 = 1;
    } else { /* default to u32 */
        want64 = 0;
    }

    const char *base = base_pref ? base_pref : "auto";
    if (strcaseeq(base, "auto")) base = "hex"; /* default */

    /* prepare raw bytes */
    uint8_t buf[64];     /* enough for up to 512-bit */
    size_t buflen = 0;

    if (strcaseeq(can, "sha1")) {
        sha1_hash(data, len, buf);
        buflen = 20;
        if (!want64) buflen = 4;
        else if (want64 && buflen < 8) buflen = 8;
    } else if (strcaseeq(can, "sha256")) {
        sha256_hash(data, len, buf);
        buflen = 32;
        if (!want64) buflen = 4;
        else if (want64 && buflen < 8) buflen = 8;
    } else if (strcaseeq(can, "sha512")) {
        sha512_hash(data, len, buf);
        buflen = 64;
        if (!want64) buflen = 4;
        else if (want64 && buflen < 8) buflen = 8;
    } else if (want64) {
        uint64_t v = compute_u64_by_alg(can, data, len);
        u64_to_be(v, buf);
        buflen = 8;
    } else {
        uint32_t v = compute_u32_by_alg(can, data, len);
        u32_to_be(v, buf);
        buflen = 4;
    }

    if (strcaseeq(base, "hex")) {
        size_t needed = buflen*2 + 1;
        if (outlen < needed) return -2;
        hex_encode_lower(buf, buflen, out);
        return 0;
    } else if (strcaseeq(base, "base64")) {
        if (base64_encode(buf, buflen, out, outlen) != 0) return -3;
        return 0;
    } else if (strcaseeq(base, "base62")) {
        if (base62_encode(buf, buflen, out, outlen) != 0) return -4;
        return 0;
    } else if (strcaseeq(base, "base36")) {
        if (base36_encode(buf, buflen, out, outlen) != 0) return -5;
        return 0;
    } else {
        /* unknown base: fallback to hex */
        size_t needed = buflen*2 + 1;
        if (outlen < needed) return -2;
        hex_encode_lower(buf, buflen, out);
        return 0;
    }
}

/* thread-safe helper: returns a pointer to thread-local static buffer
 * Uses platform-specific thread-local storage.
 */
char *fossil_cryptic_hash_hex_auto(const void *data, size_t len, const char *alg) {
#if defined(_WIN32)
    __declspec(thread) static char tmp[129];
#elif defined(__APPLE__) || defined(__unix__) || defined(__linux__)
    static __thread char tmp[129];
#else
#   if defined(__STDC_NO_THREADS__)
        /* fallback: not thread-safe */
        static char tmp[129];
#   else
        _Thread_local static char tmp[129];
#   endif
#endif
    if (!data) { tmp[0] = '\0'; return tmp; }
    fossil_cryptic_hash_to_str(data, len, alg, "auto", "hex", tmp, sizeof(tmp));
    return tmp;
}

/* ------------------------ options struct API ------------------------ */

/*
 * int fossil_cryptic_hash_with_opts(const void *data, size_t len,
 *                                   const fossil_cryptic_hash_opts *opts,
 *                                   char *out, size_t outlen)
 *
 * Compute a hash and encode to string according to options struct.
 * Returns 0 on success, non-zero on error.
 */
int fossil_cryptic_hash_with_opts(const void *data, size_t len,
                                  const fossil_cryptic_hash_opts *opts,
                                  char *out, size_t outlen)
{
    if (!opts) return fossil_cryptic_hash_to_str(data, len, NULL, NULL, NULL, out, outlen);
    return fossil_cryptic_hash_to_str(data, len, opts->alg, opts->bits, opts->base, out, outlen);
}
