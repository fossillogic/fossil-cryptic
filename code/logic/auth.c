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
#include <stdlib.h>
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
void fossil_cryptic_auth_pbkdf2_sha256(const uint8_t *password, size_t pass_len,
                                       const uint8_t *salt, size_t salt_len,
                                       uint32_t iterations, uint8_t *out, size_t out_len) {
    if (!password || !salt || !out || iterations == 0) {
        if (out && out_len) memset(out, 0, out_len);
        return;
    }

    uint32_t block_count = (uint32_t)((out_len + 31) / 32);
    uint8_t U[32], T[32];
    uint8_t salt_block[64]; // small stack buffer for most salts
    size_t i, j, k;

    for (i = 1; i <= block_count; i++) {
        size_t base_len = 0;

        if (salt_len + 4 <= sizeof(salt_block)) {
            // Use stack buffer for small salts
            memcpy(salt_block, salt, salt_len);
            salt_block[salt_len + 0] = (uint8_t)((i >> 24) & 0xFF);
            salt_block[salt_len + 1] = (uint8_t)((i >> 16) & 0xFF);
            salt_block[salt_len + 2] = (uint8_t)((i >> 8) & 0xFF);
            salt_block[salt_len + 3] = (uint8_t)(i & 0xFF);
            base_len = salt_len + 4;

            fossil_cryptic_auth_hmac_sha256(password, pass_len, salt_block, base_len, U);
        } else {
            // Large salt: allocate temporary buffer
            size_t tmp_size = salt_len + 4;
            uint8_t *tmp = (uint8_t *)malloc(tmp_size);
            if (!tmp) {
                // allocation failed: zero output and exit
                memset(out, 0, out_len);
                return;
            }

            memcpy(tmp, salt, salt_len);
            tmp[salt_len + 0] = (uint8_t)((i >> 24) & 0xFF);
            tmp[salt_len + 1] = (uint8_t)((i >> 16) & 0xFF);
            tmp[salt_len + 2] = (uint8_t)((i >> 8) & 0xFF);
            tmp[salt_len + 3] = (uint8_t)(i & 0xFF);

            fossil_cryptic_auth_hmac_sha256(password, pass_len, tmp, tmp_size, U);
            free(tmp);
        }

        memcpy(T, U, 32);

        for (j = 1; j < iterations; j++) {
            fossil_cryptic_auth_hmac_sha256(password, pass_len, U, 32, U);
            for (k = 0; k < 32; k++) T[k] ^= U[k];
        }

        size_t offset = (i - 1) * 32;
        size_t to_copy = (out_len - offset) < 32 ? (out_len - offset) : 32;
        memcpy(out + offset, T, to_copy);
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
    /* apply clamp: clear bits as per RFC 8439, section 2.5.1 */
    uint8_t clamped[16];
    memcpy(clamped, rkey, 16);
    clamped[3]  &= 15;
    clamped[7]  &= 15;
    clamped[11] &= 15;
    clamped[15] &= 15;
    clamped[4]  &= 252;
    clamped[8]  &= 252;
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
        uint8_t block[16] = {0};
        memcpy(block, ctx->buffer, ctx->leftover);
        block[ctx->leftover] = 1;
        fossil_poly1305_blocks(ctx, block, 16);
    }

    /* Fully carry h to canonical form */
    uint64_t h0 = ctx->h[0];
    uint64_t h1 = ctx->h[1];
    uint64_t h2 = ctx->h[2];
    uint64_t h3 = ctx->h[3];
    uint64_t h4 = ctx->h[4];

    /* Final carry propagation */
    uint64_t c;
    c = h1 >> 26; h1 &= 0x3ffffff; h2 += c;
    c = h2 >> 26; h2 &= 0x3ffffff; h3 += c;
    c = h3 >> 26; h3 &= 0x3ffffff; h4 += c;
    c = h4 >> 26; h4 &= 0x3ffffff; h0 += c * 5;
    c = h0 >> 26; h0 &= 0x3ffffff; h1 += c;

    /* Now combine into 128-bit little-endian number */
    uint64_t acc0 = h0 | (h1 << 26);
    uint64_t acc1 = (h1 >> 38) | (h2 << 12) | (h3 << 38); /* folded limbs */

    /* add s (pad) */
    uint64_t s0 = ((uint64_t)ctx->pad[0]) | ((uint64_t)ctx->pad[1] << 32);
    uint64_t s1 = ((uint64_t)ctx->pad[2]) | ((uint64_t)ctx->pad[3] << 32);

    acc0 += s0;
    uint64_t carry = (acc0 < s0);
    acc1 += s1 + carry;

    /* Store tag little-endian 16 bytes */
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

/* Rotate macro */
#ifndef ROTL32
#define ROTL32(v, n) (((v) << (n)) | ((v) >> (32 - (n))))
#endif

/* ChaCha20 quarter round */
#define QR(a,b,c,d) \
    a += b; d ^= a; d = ROTL32(d,16); \
    c += d; b ^= c; b = ROTL32(b,12); \
    a += b; d ^= a; d = ROTL32(d,8);  \
    c += d; b ^= c; b = ROTL32(b,7);

static uint32_t load32_le(const uint8_t *p) {
    return ((uint32_t)p[0]) | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void store32_le(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v & 0xFF);
    p[1] = (uint8_t)((v >> 8) & 0xFF);
    p[2] = (uint8_t)((v >> 16) & 0xFF);
    p[3] = (uint8_t)((v >> 24) & 0xFF);
}

/* Constants for ChaCha20 (ASCII of "expand 32-byte k") */
static const uint8_t chacha20_const[16] = { 'e','x','p','a','n','d',' ','3','2','-','b','y','t','e',' ','k' };

/* chacha20 block: produces 64 bytes */
void fossil_cryptic_auth_chacha20_block(const uint8_t key[32], const uint8_t nonce[12], uint32_t counter, uint8_t out[64]) {
    uint32_t state[16];
    uint32_t working[16];
    int i;

    /* state setup */
    state[0]  = load32_le(chacha20_const + 0);
    state[1]  = load32_le(chacha20_const + 4);
    state[2]  = load32_le(chacha20_const + 8);
    state[3]  = load32_le(chacha20_const + 12);

    for (i = 0; i < 8; i++) {
        state[4 + i] = load32_le(key + i*4);
    }

    state[12] = counter;
    state[13] = load32_le(nonce + 0);
    state[14] = load32_le(nonce + 4);
    state[15] = load32_le(nonce + 8);

    /* working copy */
    for (i = 0; i < 16; ++i) working[i] = state[i];

    /* 20 rounds (10 double rounds) */
    for (i = 0; i < 10; ++i) {
        /* column rounds */
        QR(working[0], working[4], working[8],  working[12]);
        QR(working[1], working[5], working[9],  working[13]);
        QR(working[2], working[6], working[10], working[14]);
        QR(working[3], working[7], working[11], working[15]);
        /* diagonal rounds */
        QR(working[0], working[5], working[10], working[15]);
        QR(working[1], working[6], working[11], working[12]);
        QR(working[2], working[7], working[8],  working[13]);
        QR(working[3], working[4], working[9],  working[14]);
    }

    /* add & serialize */
    for (i = 0; i < 16; ++i) {
        uint32_t v = working[i] + state[i];
        store32_le(out + i*4, v);
    }
}

/* XOR keystream with input (streaming) */
void fossil_cryptic_auth_chacha20_xor(const uint8_t key[32], const uint8_t nonce[12], uint32_t counter, const uint8_t *in, uint8_t *out, size_t len) {
    uint8_t block[64];
    size_t offset = 0;
    uint32_t ctr = counter;

    while (len > 0) {
        fossil_cryptic_auth_chacha20_block(key, nonce, ctr, block);
        size_t chunk = (len > 64) ? 64 : len;
        for (size_t i = 0; i < chunk; ++i) {
            out[offset + i] = in[offset + i] ^ block[i];
        }
        len -= chunk;
        offset += chunk;
        ctr++;
    }
}

/* Helper: write 64-bit little-endian */
static void store64_le(uint8_t *p, uint64_t v) {
    p[0] = (uint8_t)(v & 0xFF);
    p[1] = (uint8_t)((v >> 8) & 0xFF);
    p[2] = (uint8_t)((v >> 16) & 0xFF);
    p[3] = (uint8_t)((v >> 24) & 0xFF);
    p[4] = (uint8_t)((v >> 32) & 0xFF);
    p[5] = (uint8_t)((v >> 40) & 0xFF);
    p[6] = (uint8_t)((v >> 48) & 0xFF);
    p[7] = (uint8_t)((v >> 56) & 0xFF);
}

/* AEAD encrypt */
void fossil_cryptic_auth_chacha20_poly1305_encrypt(const uint8_t key[32], const uint8_t nonce[12], const uint8_t *aad, size_t aad_len, const uint8_t *plaintext, size_t pt_len, uint8_t *ciphertext, uint8_t tag[16]) {
    uint8_t poly_key[32];
    uint8_t zero_block[64] = {0};

    /* Derive Poly1305 key: chacha20 block with counter = 0 */
    fossil_cryptic_auth_chacha20_block(key, nonce, 0, zero_block);
    memcpy(poly_key, zero_block, 32);

    /* Encrypt plaintext using ChaCha20 with counter = 1 */
    if (pt_len > 0) {
        fossil_cryptic_auth_chacha20_xor(key, nonce, 1, plaintext, ciphertext, pt_len);
    } else {
        /* nothing to do */
    }

    /* Compute Poly1305 tag over: aad || pad16 || ciphertext || pad16 || len(aad) (64-bit LE) || len(ciphertext) (64-bit LE) */
    fossil_cryptic_auth_poly1305_ctx_t pctx;
    fossil_cryptic_auth_poly1305_init(&pctx, poly_key);

    /* AAD */
    if (aad_len) fossil_cryptic_auth_poly1305_update(&pctx, aad, aad_len);
    /* pad to 16 */
    if (aad_len % 16) {
        uint8_t zeros[16] = {0};
        fossil_cryptic_auth_poly1305_update(&pctx, zeros, 16 - (aad_len % 16));
    }

    /* Ciphertext */
    if (pt_len) fossil_cryptic_auth_poly1305_update(&pctx, ciphertext, pt_len);
    if (pt_len % 16) {
        uint8_t zeros[16] = {0};
        fossil_cryptic_auth_poly1305_update(&pctx, zeros, 16 - (pt_len % 16));
    }

    /* lengths: 64-bit little endian */
    uint8_t len_block[16];
    store64_le(len_block + 0, (uint64_t)aad_len);
    store64_le(len_block + 8, (uint64_t)pt_len);
    fossil_cryptic_auth_poly1305_update(&pctx, len_block, 16);

    fossil_cryptic_auth_poly1305_finish(&pctx, tag);
}

/* AEAD decrypt: verify tag, then decrypt on success */
int fossil_cryptic_auth_chacha20_poly1305_decrypt(const uint8_t key[32], const uint8_t nonce[12], const uint8_t *aad, size_t aad_len, const uint8_t *ciphertext, size_t ct_len, uint8_t *plaintext, const uint8_t tag[16]) {
    uint8_t poly_key[32];
    uint8_t zero_block[64] = {0};
    uint8_t calc_tag[16];

    /* Derive Poly1305 key */
    fossil_cryptic_auth_chacha20_block(key, nonce, 0, zero_block);
    memcpy(poly_key, zero_block, 32);

    /* Compute tag over AAD and ciphertext (same as encrypt) */
    fossil_cryptic_auth_poly1305_ctx_t pctx;
    fossil_cryptic_auth_poly1305_init(&pctx, poly_key);

    if (aad_len) fossil_cryptic_auth_poly1305_update(&pctx, aad, aad_len);
    if (aad_len % 16) {
        uint8_t zeros[16] = {0};
        fossil_cryptic_auth_poly1305_update(&pctx, zeros, 16 - (aad_len % 16));
    }

    if (ct_len) fossil_cryptic_auth_poly1305_update(&pctx, ciphertext, ct_len);
    if (ct_len % 16) {
        uint8_t zeros[16] = {0};
        fossil_cryptic_auth_poly1305_update(&pctx, zeros, 16 - (ct_len % 16));
    }

    uint8_t len_block[16];
    store64_le(len_block + 0, (uint64_t)aad_len);
    store64_le(len_block + 8, (uint64_t)ct_len);
    fossil_cryptic_auth_poly1305_update(&pctx, len_block, 16);

    fossil_cryptic_auth_poly1305_finish(&pctx, calc_tag);

    /* Constant-time compare */
    if (!fossil_cryptic_auth_consttime_equal(calc_tag, tag, 16)) {
        /* tag mismatch - do not decrypt */
        return 0;
    }

    /* Tag valid -> decrypt ciphertext using ChaCha20 counter = 1 */
    if (ct_len > 0) {
        fossil_cryptic_auth_chacha20_xor(key, nonce, 1, ciphertext, plaintext, ct_len);
    }

    return 1;
}
