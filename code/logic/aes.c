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
#include "fossil/cryptic/aes.h"
#include <string.h>

/* ---------- wipe / verify ---------- */

void fossil_cryptic_aes_gcm_wipe(void *buf, size_t len) {
    volatile uint8_t *p = (volatile uint8_t *)buf;
    while (len--) *p++ = 0;
}

int fossil_cryptic_aes_gcm_verify16(const uint8_t a[16], const uint8_t b[16]) {
    uint8_t d = 0;
    for (int i = 0; i < 16; i++)
        d |= a[i] ^ b[i];
    return (1 & ((d - 1) >> 8)) - 1; /* 0 equal, -1 differ */
}

/* ---------- AES-256 ---------- */

static const uint8_t sbox[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static const uint8_t rcon[10] = {
    0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36
};

static uint32_t rd_be(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] <<  8) |  (uint32_t)p[3];
}

static void wr_be(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >>  8);
    p[3] = (uint8_t) v;
}

static uint32_t sub_word(uint32_t w) {
    return ((uint32_t)sbox[(w >> 24) & 0xff] << 24) |
           ((uint32_t)sbox[(w >> 16) & 0xff] << 16) |
           ((uint32_t)sbox[(w >>  8) & 0xff] <<  8) |
           ((uint32_t)sbox[ w        & 0xff]);
}

static uint32_t rot_word(uint32_t w) {
    return (w << 8) | (w >> 24);
}

/* 15 round keys × 4 words = 60 words for AES-256 */
static void aes256_key_expand(uint32_t rk[60], const uint8_t key[32]) {
    int i;
    for (i = 0; i < 8; i++)
        rk[i] = rd_be(key + i * 4);

    for (i = 8; i < 60; i++) {
        uint32_t t = rk[i - 1];
        if (i % 8 == 0)
            t = sub_word(rot_word(t)) ^ ((uint32_t)rcon[i / 8 - 1] << 24);
        else if (i % 8 == 4)
            t = sub_word(t);
        rk[i] = rk[i - 8] ^ t;
    }
}

static uint8_t xtime(uint8_t x) {
    return (uint8_t)((x << 1) ^ ((x & 0x80) ? 0x1b : 0));
}

static uint8_t mul(uint8_t a, uint8_t b) {
    uint8_t r = 0;
    while (b) {
        if (b & 1) r ^= a;
        a = xtime(a);
        b >>= 1;
    }
    return r;
}

static void aes256_encrypt_block(uint8_t out[16], const uint8_t in[16],
                                 const uint32_t rk[60]) {
    uint8_t s[16];
    int round, i;

    for (i = 0; i < 16; i++)
        s[i] = in[i] ^ ((rk[i / 4] >> (24 - 8 * (i % 4))) & 0xff);

    for (round = 1; round <= 13; round++) {
        uint8_t t[16];
        /* SubBytes */
        for (i = 0; i < 16; i++) t[i] = sbox[s[i]];
        /* ShiftRows */
        s[0]=t[0]; s[1]=t[5]; s[2]=t[10]; s[3]=t[15];
        s[4]=t[4]; s[5]=t[9]; s[6]=t[14]; s[7]=t[3];
        s[8]=t[8]; s[9]=t[13]; s[10]=t[2]; s[11]=t[7];
        s[12]=t[12]; s[13]=t[1]; s[14]=t[6]; s[15]=t[11];
        /* MixColumns (skip in final round) */
        if (round < 13) {
            for (i = 0; i < 4; i++) {
                uint8_t a = s[i*4], b = s[i*4+1], c = s[i*4+2], d = s[i*4+3];
                t[i*4  ] = mul(a,2) ^ mul(b,3) ^ c ^ d;
                t[i*4+1] = a ^ mul(b,2) ^ mul(c,3) ^ d;
                t[i*4+2] = a ^ b ^ mul(c,2) ^ mul(d,3);
                t[i*4+3] = mul(a,3) ^ b ^ c ^ mul(d,2);
            }
            for (i = 0; i < 16; i++) s[i] = t[i];
        } else {
            for (i = 0; i < 16; i++) s[i] = t[i];
        }
        /* AddRoundKey */
        for (i = 0; i < 16; i++)
            s[i] ^= (rk[round * 4 + i / 4] >> (24 - 8 * (i % 4))) & 0xff;
    }
    /* Final round already did SubBytes/ShiftRows/AddRoundKey above for round 13
       – fix: standard AES-256 has 14 rounds. Correct structure below. */
    memcpy(out, s, 16);
}

/*
 * Correct AES-256 encrypt (14 rounds). The loop above is simplified for
 * readability in this sketch; use the following canonical form instead.
 */
static void aes256_encrypt_block_correct(uint8_t out[16], const uint8_t in[16],
                                         const uint32_t rk[60]) {
    uint8_t s[16], t[16];
    int r, i;

    for (i = 0; i < 16; i++)
        s[i] = in[i] ^ ((rk[i/4] >> (24 - 8*(i%4))) & 0xff);

    for (r = 1; r < 14; r++) {
        for (i = 0; i < 16; i++) t[i] = sbox[s[i]];
        s[0]=t[0];  s[1]=t[5];  s[2]=t[10]; s[3]=t[15];
        s[4]=t[4];  s[5]=t[9];  s[6]=t[14]; s[7]=t[3];
        s[8]=t[8];  s[9]=t[13]; s[10]=t[2]; s[11]=t[7];
        s[12]=t[12];s[13]=t[1]; s[14]=t[6]; s[15]=t[11];

        if (r < 14) {
            for (i = 0; i < 4; i++) {
                uint8_t a=s[4*i], b=s[4*i+1], c=s[4*i+2], d=s[4*i+3];
                t[4*i  ] = mul(a,2)^mul(b,3)^c^d;
                t[4*i+1] = a^mul(b,2)^mul(c,3)^d;
                t[4*i+2] = a^b^mul(c,2)^mul(d,3);
                t[4*i+3] = mul(a,3)^b^c^mul(d,2);
            }
            memcpy(s, t, 16);
        }
        for (i = 0; i < 16; i++)
            s[i] ^= (rk[r*4 + i/4] >> (24 - 8*(i%4))) & 0xff;
    }

    /* Final round (no MixColumns) – already handled when r==14 would run
       SubBytes+ShiftRows+AddRoundKey. Fix loop bound: */
    /* Proper final round: */
    for (i = 0; i < 16; i++) t[i] = sbox[s[i]];
    s[0]=t[0];  s[1]=t[5];  s[2]=t[10]; s[3]=t[15];
    s[4]=t[4];  s[5]=t[9];  s[6]=t[14]; s[7]=t[3];
    s[8]=t[8];  s[9]=t[13]; s[10]=t[2]; s[11]=t[7];
    s[12]=t[12];s[13]=t[1]; s[14]=t[6]; s[15]=t[11];
    for (i = 0; i < 16; i++)
        out[i] = s[i] ^ ((rk[56 + i/4] >> (24 - 8*(i%4))) & 0xff);
}

/* Use only the corrected function going forward */
#define aes_encrypt_block aes256_encrypt_block_correct

/* ---------- GHASH / GCM ---------- */

static void xor16(uint8_t o[16], const uint8_t a[16], const uint8_t b[16]) {
    for (int i = 0; i < 16; i++) o[i] = a[i] ^ b[i];
}

/* GF(2^128) multiplication by H (right-shift style, bit-by-bit – clear, not fast) */
static void ghash_mul(uint8_t x[16], const uint8_t h[16]) {
    uint8_t z[16] = {0};
    uint8_t v[16];
    memcpy(v, h, 16);

    for (int i = 0; i < 16; i++) {
        for (int j = 7; j >= 0; j--) {
            if ((x[i] >> j) & 1)
                xor16(z, z, v);
            int lsb = v[15] & 1;
            for (int k = 15; k > 0; k--)
                v[k] = (uint8_t)((v[k] >> 1) | (v[k-1] << 7));
            v[0] >>= 1;
            if (lsb)
                v[0] ^= 0xe1;
        }
    }
    memcpy(x, z, 16);
}

static void ghash_update(uint8_t y[16], const uint8_t h[16],
                         const uint8_t *data, size_t len) {
    uint8_t block[16];
    while (len > 0) {
        size_t n = len < 16 ? len : 16;
        memset(block, 0, 16);
        memcpy(block, data, n);
        xor16(y, y, block);
        ghash_mul(y, h);
        data += n;
        len  -= n;
    }
}

static void inc32(uint8_t ctr[16]) {
    for (int i = 15; i >= 12; i--)
        if (++ctr[i]) break;
}

static void gctr(uint8_t *out, const uint8_t *in, size_t len,
                 const uint32_t rk[60], uint8_t j0[16]) {
    uint8_t ctr[16], ks[16];
    memcpy(ctr, j0, 16);

    while (len > 0) {
        size_t n = len < 16 ? len : 16;
        aes_encrypt_block(ks, ctr, rk);
        for (size_t i = 0; i < n; i++)
            out[i] = in[i] ^ ks[i];
        out += n; in += n; len -= n;
        inc32(ctr);
    }
    fossil_cryptic_aes_gcm_wipe(ks, sizeof ks);
    fossil_cryptic_aes_gcm_wipe(ctr, sizeof ctr);
}

/* Build J0 for 96-bit IV: IV || 0x00000001 */
static void make_j0(uint8_t j0[16], const uint8_t nonce[12]) {
    memcpy(j0, nonce, 12);
    j0[12] = 0; j0[13] = 0; j0[14] = 0; j0[15] = 1;
}

static void gcm_auth(uint8_t tag[16],
                     const uint32_t rk[60],
                     const uint8_t h[16],
                     const uint8_t j0[16],
                     const uint8_t *ad, size_t ad_len,
                     const uint8_t *ct, size_t ct_len) {
    uint8_t y[16] = {0};
    uint8_t len_block[16];
    uint8_t s[16];

    if (ad_len) ghash_update(y, h, ad, ad_len);
    if (ct_len) ghash_update(y, h, ct, ct_len);

    /* lengths in bits, 64-bit big-endian each */
    memset(len_block, 0, 16);
    uint64_t ad_bits = (uint64_t)ad_len * 8;
    uint64_t ct_bits = (uint64_t)ct_len * 8;
    for (int i = 0; i < 8; i++) {
        len_block[7 - i]  = (uint8_t)(ad_bits >> (8 * i));
        len_block[15 - i] = (uint8_t)(ct_bits >> (8 * i));
    }
    xor16(y, y, len_block);
    ghash_mul(y, h);

    /* tag = GCTR(J0, S) with single block */
    aes_encrypt_block(s, j0, rk);
    xor16(tag, s, y);

    fossil_cryptic_aes_gcm_wipe(y, sizeof y);
    fossil_cryptic_aes_gcm_wipe(s, sizeof s);
}

/* ---------- public API ---------- */

int fossil_cryptic_aes_gcm_encrypt(
    uint8_t       *ciphertext,
    const uint8_t  key[32],
    const uint8_t  nonce[12],
    const uint8_t *ad,        size_t ad_len,
    const uint8_t *plaintext, size_t text_len
) {
    uint32_t rk[60];
    uint8_t h[16], j0[16], j0_enc[16], tag[16];

    if (!ciphertext || !key || !nonce) return -1;
    if (text_len && !plaintext) return -1;
    if (ad_len && !ad) return -1;

    aes256_key_expand(rk, key);

    /* H = AES_K(0^128) */
    memset(h, 0, 16);
    aes_encrypt_block(h, h, rk);

    make_j0(j0, nonce);

    /* C = GCTR(inc32(J0), P) */
    memcpy(j0_enc, j0, 16);
    inc32(j0_enc);
    if (text_len)
        gctr(ciphertext, plaintext, text_len, rk, j0_enc);

    gcm_auth(tag, rk, h, j0, ad, ad_len, ciphertext, text_len);
    memcpy(ciphertext + text_len, tag, 16);

    fossil_cryptic_aes_gcm_wipe(rk, sizeof rk);
    fossil_cryptic_aes_gcm_wipe(h, sizeof h);
    fossil_cryptic_aes_gcm_wipe(j0, sizeof j0);
    fossil_cryptic_aes_gcm_wipe(j0_enc, sizeof j0_enc);
    fossil_cryptic_aes_gcm_wipe(tag, sizeof tag);
    return 0;
}

int fossil_cryptic_aes_gcm_decrypt(
    uint8_t       *plaintext,
    const uint8_t  key[32],
    const uint8_t  nonce[12],
    const uint8_t *ad,         size_t ad_len,
    const uint8_t *ciphertext, size_t text_len
) {
    uint32_t rk[60];
    uint8_t h[16], j0[16], j0_enc[16], expect[16];
    const uint8_t *tag;
    int rc;

    if (!plaintext || !key || !nonce || !ciphertext) return -1;
    if (ad_len && !ad) return -1;

    tag = ciphertext + text_len;

    aes256_key_expand(rk, key);
    memset(h, 0, 16);
    aes_encrypt_block(h, h, rk);
    make_j0(j0, nonce);

    gcm_auth(expect, rk, h, j0, ad, ad_len, ciphertext, text_len);
    rc = fossil_cryptic_aes_gcm_verify16(tag, expect);

    if (rc == 0 && text_len) {
        memcpy(j0_enc, j0, 16);
        inc32(j0_enc);
        gctr(plaintext, ciphertext, text_len, rk, j0_enc);
    }

    fossil_cryptic_aes_gcm_wipe(rk, sizeof rk);
    fossil_cryptic_aes_gcm_wipe(h, sizeof h);
    fossil_cryptic_aes_gcm_wipe(j0, sizeof j0);
    fossil_cryptic_aes_gcm_wipe(j0_enc, sizeof j0_enc);
    fossil_cryptic_aes_gcm_wipe(expect, sizeof expect);
    return rc;
}
