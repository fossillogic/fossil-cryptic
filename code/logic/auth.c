/*
 * -----------------------------------------------------------------------------
 * Project: Fossil Logic
 *
 * This file is part of the Fossil Logic project, which aims to develop high-
 * performance, cross-platform applications and libraries. The code contained
 * herein is subject to the terms and conditions defined in the project license.
 *
 * Author: Michael Gene Brockus (Dreamer)
 *
 * Copyright (C) 2024 Fossil Logic. All rights reserved.
 * -----------------------------------------------------------------------------
 */
#include "fossil/cryptic/auth.h"
#include "fossil/cryptic/hash.h"
#include <string.h>

#include "fossil_cryptic_auth.h"
#include "fossil_cryptic_hash.h"  /* Uses SHA-256 implementation */
#include <string.h>
#include <stdint.h>

/* ----------------------
 * HMAC-SHA256 (unchanged)
 * ---------------------- */
void fossil_cryptic_auth_hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len, uint8_t out[32]) {
    uint8_t k_ipad[64], k_opad[64], tk[32];
    size_t i;

    if (!key) { memset(out, 0, 32); return; }

    /* If key longer than blocksize, shorten it */
    if (key_len > 64) {
        fossil_cryptic_hash_sha256(key, key_len, tk);
        key = tk;
        key_len = 32;
    }

    /* Prepare pads */
    memset(k_ipad, 0x36, 64);
    memset(k_opad, 0x5c, 64);

    for (i = 0; i < key_len; i++) {
        k_ipad[i] ^= key[i];
        k_opad[i] ^= key[i];
    }

    /* Inner */
    {
        fossil_cryptic_hash_sha256_ctx_t ctx;
        uint8_t inner[32];
        fossil_cryptic_hash_sha256_init(&ctx);
        fossil_cryptic_hash_sha256_update(&ctx, k_ipad, 64);
        fossil_cryptic_hash_sha256_update(&ctx, data, data_len);
        fossil_cryptic_hash_sha256_final(&ctx, inner);

        /* Outer */
        fossil_cryptic_hash_sha256_init(&ctx);
        fossil_cryptic_hash_sha256_update(&ctx, k_opad, 64);
        fossil_cryptic_hash_sha256_update(&ctx, inner, 32);
        fossil_cryptic_hash_sha256_final(&ctx, out);
    }
}

/* ----------------------
 * PBKDF2-HMAC-SHA256 (unchanged)
 * ---------------------- */
void fossil_cryptic_auth_pbkdf2_sha256(const uint8_t *password, size_t pass_len, const uint8_t *salt, size_t salt_len, uint32_t iterations, uint8_t *out, size_t out_len) {
    if (!password || !salt || !out || iterations == 0) {
        if (out && out_len) memset(out, 0, out_len);
        return;
    }

    uint32_t block_count = (uint32_t)((out_len + 31) / 32);
    uint8_t U[32], T[32];
    /* salt_block holds salt || 4-byte BE block index. Keep small stack allocation. */
    uint8_t salt_block[64];
    size_t i, j, k;

    if (salt_len + 4 > sizeof(salt_block)) {
        /* very long salt - process by copying only what fits (rare) */
        memcpy(salt_block, salt, sizeof(salt_block) - 4);
    } else {
        memcpy(salt_block, salt, salt_len);
    }

    for (i = 1; i <= block_count; i++) {
        /* append big-endian block index */
        size_t base_len = salt_len;
        if (salt_len + 4 <= sizeof(salt_block)) {
            salt_block[salt_len + 0] = (uint8_t)((i >> 24) & 0xFF);
            salt_block[salt_len + 1] = (uint8_t)((i >> 16) & 0xFF);
            salt_block[salt_len + 2] = (uint8_t)((i >> 8) & 0xFF);
            salt_block[salt_len + 3] = (uint8_t)((i) & 0xFF);
            base_len = salt_len + 4;
        } else {
            /* fallback: use a temporary buffer */
            uint8_t tmp[8];
            memcpy(tmp, salt, salt_len);
            tmp[salt_len + 0] = (uint8_t)((i >> 24) & 0xFF);
            tmp[salt_len + 1] = (uint8_t)((i >> 16) & 0xFF);
            tmp[salt_len + 2] = (uint8_t)((i >> 8) & 0xFF);
            tmp[salt_len + 3] = (uint8_t)((i) & 0xFF);
            fossil_cryptic_auth_hmac_sha256(password, pass_len, tmp, salt_len + 4, U);
            memcpy(T, U, 32);
            for (j = 1; j < iterations; j++) {
                fossil_cryptic_auth_hmac_sha256(password, pass_len, U, 32, U);
                for (k = 0; k < 32; k++) T[k] ^= U[k];
            }
            size_t offset = (i - 1) * 32;
            size_t to_copy = (out_len - offset) < 32 ? (out_len - offset) : 32;
            memcpy(out + offset, T, to_copy);
            continue;
        }

        fossil_cryptic_auth_hmac_sha256(password, pass_len, salt_block, base_len, U);
        memcpy(T, U, 32);

        for (j = 1; j < iterations; j++) {
            fossil_cryptic_auth_hmac_sha256(password, pass_len, U, 32, U);
            for (k = 0; k < 32; k++) {
                T[k] ^= U[k];
            }
        }

        {
            size_t offset = (i - 1) * 32;
            size_t to_copy = (out_len - offset) < 32 ? (out_len - offset) : 32;
            memcpy(out + offset, T, to_copy);
        }
    }
}

/* ----------------------
 * Poly1305 implementation (small, limb-based)
 *
 * Reference behavior: one-shot and streaming. Produces 16-byte tag.
 * This implementation is intended to be portable and dependency-free.
 * ---------------------- */

/* Internal: load 32-bit little-endian */
static uint32_t fossil_load32_le(const uint8_t *p) {
    return ((uint32_t)p[0]) | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* Internal: store 32-bit little-endian */
static void fossil_store32_le(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v & 0xFF);
    p[1] = (uint8_t)((v >> 8) & 0xFF);
    p[2] = (uint8_t)((v >> 16) & 0xFF);
    p[3] = (uint8_t)((v >> 24) & 0xFF);
}

/*
 * Clamp r per spec: clear certain bits:
 * r &= 0x0ffffffc0ffffffc0ffffffc0fffffff
 * We extract into 5 26-bit limbs after clamping.
 */
static void fossil_poly1305_keyclamp_and_load_r(const uint8_t rkey[16], uint32_t r[5]) {
    /* rkey is 16 bytes little-endian */
    uint64_t t0 = (uint64_t)fossil_load32_le(rkey + 0) | ((uint64_t)fossil_load32_le(rkey + 4) << 32);
    uint64_t t1 = (uint64_t)fossil_load32_le(rkey + 8) | ((uint64_t)fossil_load32_le(rkey + 12) << 32);

    /* apply clamp: clear bits 0..127 as needed by mask:
       mask bytes: 0x0ffffffc0ffffffc0ffffffc0fffffff (in 130-bit form)
       Simpler approach: clear specific bits in bytes as per RFC */
    uint8_t clamped[16];
    memcpy(clamped, rkey, 16);
    clamped[3] &= 15;
    clamped[7] &= 15;
    clamped[11] &= 15;
    clamped[15] &= 15;
    clamped[4] &= 252;
    clamped[8] &= 252;
    clamped[12] &= 252;

    /* now load as 5 26-bit limbs little-endian: r0 + r1*2^26 + r2*2^52 ... */
    uint32_t t[4];
    t[0] = fossil_load32_le(clamped + 0);
    t[1] = fossil_load32_le(clamped + 4);
    t[2] = fossil_load32_le(clamped + 8);
    t[3] = fossil_load32_le(clamped + 12);

    uint64_t r0 = (uint64_t)(t[0] & 0x3ffffff); /* 26 bits */
    uint64_t r1 = (uint64_t)(((t[0] >> 26) | (t[1] << 6)) & 0x3ffffff);
    uint64_t r2 = (uint64_t)(((t[1] >> 20) | (t[2] << 12)) & 0x3ffffff);
    uint64_t r3 = (uint64_t)(((t[2] >> 14) | (t[3] << 18)) & 0x3ffffff);
    uint64_t r4 = (uint64_t)((t[3] >> 8) & 0x0ffffff);

    r[0] = (uint32_t)r0;
    r[1] = (uint32_t)r1;
    r[2] = (uint32_t)r2;
    r[3] = (uint32_t)r3;
    r[4] = (uint32_t)r4;
}

/* Multiply accumulator h by r and add block, modulo 2^130-5.
   Using 64-bit temporaries. This is a straightforward, small poly1305 core. */
static void fossil_poly1305_blocks(fossil_cryptic_auth_poly1305_ctx_t *ctx, const uint8_t *m, size_t bytes) {
    /* operate on 16-byte blocks */
    while (bytes >= 16) {
        /* load block as 5 26-bit limbs, with the high bit (2^128) set */
        uint32_t t0 = fossil_load32_le(m + 0);
        uint32_t t1 = fossil_load32_le(m + 4);
        uint32_t t2 = fossil_load32_le(m + 8);
        uint32_t t3 = fossil_load32_le(m + 12);

        uint64_t b0 = (uint64_t)(t0 & 0x3ffffff);
        uint64_t b1 = (uint64_t)(((t0 >> 26) | (t1 << 6)) & 0x3ffffff);
        uint64_t b2 = (uint64_t)(((t1 >> 20) | (t2 << 12)) & 0x3ffffff);
        uint64_t b3 = (uint64_t)(((t2 >> 14) | (t3 << 18)) & 0x3ffffff);
        uint64_t b4 = (uint64_t)((t3 >> 8) | ((uint64_t)1 << 24)); /* set the 1 bit (2^128) */

        /* accumulate: h += block */
        uint64_t h0 = (uint64_t)ctx->h[0] + b0;
        uint64_t h1 = (uint64_t)ctx->h[1] + b1;
        uint64_t h2 = (uint64_t)ctx->h[2] + b2;
        uint64_t h3 = (uint64_t)ctx->h[3] + b3;
        uint64_t h4 = (uint64_t)ctx->h[4] + b4;

        /* multiply (h * r) mod (2^130 - 5) */
        uint64_t r0 = ctx->r[0];
        uint64_t r1 = ctx->r[1];
        uint64_t r2 = ctx->r[2];
        uint64_t r3 = ctx->r[3];
        uint64_t r4 = ctx->r[4];

        uint64_t d0 = h0 * r0 + h1 * (5 * r4) + h2 * (5 * r3) + h3 * (5 * r2) + h4 * (5 * r1);
        uint64_t d1 = h0 * r1 + h1 * r0 + h2 * (5 * r4) + h3 * (5 * r3) + h4 * (5 * r2);
        uint64_t d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * (5 * r4) + h4 * (5 * r3);
        uint64_t d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * (5 * r4);
        uint64_t d4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0;

        /* partial carry propagation */
        uint64_t c;

        c = (d0 >> 26); d0 &= 0x3ffffff;
        d1 += c;
        c = (d1 >> 26); d1 &= 0x3ffffff;
        d2 += c;
        c = (d2 >> 26); d2 &= 0x3ffffff;
        d3 += c;
        c = (d3 >> 26); d3 &= 0x3ffffff;
        d4 += c;
        c = (d4 >> 26); d4 &= 0x3ffffff;
        d0 += c * 5;
        c = (d0 >> 26); d0 &= 0x3ffffff;
        d1 += c;

        ctx->h[0] = (uint32_t)d0;
        ctx->h[1] = (uint32_t)d1;
        ctx->h[2] = (uint32_t)d2;
        ctx->h[3] = (uint32_t)d3;
        ctx->h[4] = (uint32_t)d4;

        m += 16;
        bytes -= 16;
    }
}

/* Initialize streaming context with key */
void fossil_cryptic_auth_poly1305_init(fossil_cryptic_auth_poly1305_ctx_t *ctx, const uint8_t key[32]) {
    if (!ctx || !key) return;
    memset(ctx, 0, sizeof(*ctx));
    /* clamp and load r (first 16 bytes) */
    fossil_poly1305_keyclamp_and_load_r(key + 0, ctx->r);
    /* load s (pad) - little endian 128-bit into pad[0..3] */
    ctx->pad[0] = fossil_load32_le(key + 16);
    ctx->pad[1] = fossil_load32_le(key + 20);
    ctx->pad[2] = fossil_load32_le(key + 24);
    ctx->pad[3] = fossil_load32_le(key + 28);
    ctx->leftover = 0;
    /* h is initialized to zero by memset above */
}

/* Update with arbitrary bytes */
void fossil_cryptic_auth_poly1305_update(fossil_cryptic_auth_poly1305_ctx_t *ctx, const uint8_t *msg, size_t msg_len) {
    if (!ctx || !msg || msg_len == 0) return;
    size_t i = 0;

    /* handle leftover */
    if (ctx->leftover) {
        size_t want = 16 - ctx->leftover;
        if (want > msg_len) want = msg_len;
        memcpy(ctx->buffer + ctx->leftover, msg, want);
        ctx->leftover += want;
        msg += want;
        msg_len -= want;
        if (ctx->leftover < 16) return;
        fossil_poly1305_blocks(ctx, ctx->buffer, 16);
        ctx->leftover = 0;
    }

    /* process full blocks directly from msg */
    if (msg_len >= 16) {
        size_t full = msg_len & ~(size_t)0xF;
        fossil_poly1305_blocks(ctx, msg, full);
        msg += full;
        msg_len -= full;
    }

    /* store leftover */
    if (msg_len) {
        memcpy(ctx->buffer, msg, msg_len);
        ctx->leftover = msg_len;
    }
}

/* Finish and produce tag */
void fossil_cryptic_auth_poly1305_finish(fossil_cryptic_auth_poly1305_ctx_t *ctx, uint8_t tag[16]) {
    if (!ctx || !tag) return;

    /* If there is leftover, process with padding and the "1" bit */
    if (ctx->leftover) {
        /* pad remainder with zeros and set the 1 bit */
        uint8_t block[16] = {0};
        memcpy(block, ctx->buffer, ctx->leftover);
        block[ctx->leftover] = 1; /* append 1 (equivalent to high bit for partial block) */
        fossil_poly1305_blocks(ctx, block, 16);
    }

    /* Fully carry h to 128-bit number */
    uint64_t h0 = ctx->h[0];
    uint64_t h1 = ctx->h[1];
    uint64_t h2 = ctx->h[2];
    uint64_t h3 = ctx->h[3];
    uint64_t h4 = ctx->h[4];

    /* combine into 128-bit little-endian number */
    uint64_t acc0 = (h0) | (h1 << 26);
    uint64_t acc1 = (h1 >> 6) | (h2 << 20);
    uint64_t acc2 = (h2 >> 12) | (h3 << 14);
    uint64_t acc3 = (h3 >> 18) | (h4 << 8);

    /* add s (pad) */
    uint64_t s0 = ((uint64_t)ctx->pad[0]) | ((uint64_t)ctx->pad[1] << 32);
    uint64_t s1 = ((uint64_t)ctx->pad[2]) | ((uint64_t)ctx->pad[3] << 32);

    acc0 += s0;
    acc1 += s1 + (acc0 < s0);

    /* store tag little-endian 16 bytes */
    fossil_store32_le(tag + 0,  (uint32_t)(acc0 & 0xFFFFFFFFu));
    fossil_store32_le(tag + 4,  (uint32_t)((acc0 >> 32) & 0xFFFFFFFFu));
    fossil_store32_le(tag + 8,  (uint32_t)(acc1 & 0xFFFFFFFFu));
    fossil_store32_le(tag + 12, (uint32_t)((acc1 >> 32) & 0xFFFFFFFFu));
}

/* One-shot convenience */
void fossil_cryptic_auth_poly1305_auth(const uint8_t key[32], const uint8_t *msg, size_t msg_len, uint8_t tag[16]) {
    fossil_cryptic_auth_poly1305_ctx_t ctx;
    fossil_cryptic_auth_poly1305_init(&ctx, key);
    fossil_cryptic_auth_poly1305_update(&ctx, msg, msg_len);
    fossil_cryptic_auth_poly1305_finish(&ctx, tag);
}

/* ----------------------
 * Constant-time compare
 * ---------------------- */
int fossil_cryptic_auth_consttime_equal(const uint8_t *a, const uint8_t *b, size_t len) {
    if (!a || !b) return 0;
    uint8_t diff = 0;
    size_t i;
    for (i = 0; i < len; i++) {
        diff |= (uint8_t)(a[i] ^ b[i]);
    }
    /* returns 1 if equal (diff == 0) */
    return (diff == 0) ? 1 : 0;
}
