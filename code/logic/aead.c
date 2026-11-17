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
#include "fossil/cryptic/aead.h"
#include "fossil/cryptic/util.h"
#include <string.h>

/* ---------- helpers ---------- */

static uint32_t load32_le(const uint8_t *p) {
    return (uint32_t)p[0]
         | (uint32_t)p[1] << 8
         | (uint32_t)p[2] << 16
         | (uint32_t)p[3] << 24;
}

static void store32_le(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static uint32_t rotl32(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

/* ---------- ChaCha20 core ---------- */

#define QR(a, b, c, d) \
    a += b; d ^= a; d = rotl32(d, 16); \
    c += d; b ^= c; b = rotl32(b, 12); \
    a += b; d ^= a; d = rotl32(d,  8); \
    c += d; b ^= c; b = rotl32(b,  7);

static void chacha20_block(uint32_t out[16], const uint32_t in[16]) {
    uint32_t x[16];
    for (int i = 0; i < 16; i++) x[i] = in[i];

    for (int i = 0; i < 10; i++) {          /* 20 rounds */
        QR(x[0], x[4], x[8],  x[12])
        QR(x[1], x[5], x[9],  x[13])
        QR(x[2], x[6], x[10], x[14])
        QR(x[3], x[7], x[11], x[15])
        QR(x[0], x[5], x[10], x[15])
        QR(x[1], x[6], x[11], x[12])
        QR(x[2], x[7], x[8],  x[13])
        QR(x[3], x[4], x[9],  x[14])
    }
    for (int i = 0; i < 16; i++)
        out[i] = x[i] + in[i];
}

/* HChaCha20 – derives the XChaCha20 subkey */
static void hchacha20(uint8_t subkey[32],
                      const uint8_t key[32],
                      const uint8_t nonce16[16]) {
    static const uint32_t c[4] = {
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574
    };
    uint32_t state[16], out[16];

    state[0] = c[0]; state[1] = c[1]; state[2] = c[2]; state[3] = c[3];
    for (int i = 0; i < 8; i++)
        state[4 + i] = load32_le(key + i * 4);
    for (int i = 0; i < 4; i++)
        state[12 + i] = load32_le(nonce16 + i * 4);

    chacha20_block(out, state);

    /* HChaCha20 output = first 4 + last 4 words */
    for (int i = 0; i < 4; i++) {
        store32_le(subkey + i * 4,      out[i]);
        store32_le(subkey + 16 + i * 4, out[12 + i]);
    }

    fossil_cryptic_util_wipe(state, sizeof(state));
    fossil_cryptic_util_wipe(out, sizeof(out));
}

/* IETF ChaCha20 (32-bit counter + 64-bit nonce part used by XChaCha20) */
static void chacha20_xor(uint8_t *out, const uint8_t *in, size_t len,
                         const uint8_t key[32],
                         const uint8_t nonce8[8],
                         uint32_t counter) {
    static const uint32_t c[4] = {
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574
    };
    uint32_t state[16], block[16];
    uint8_t keystream[64];

    state[0] = c[0]; state[1] = c[1]; state[2] = c[2]; state[3] = c[3];
    for (int i = 0; i < 8; i++)
        state[4 + i] = load32_le(key + i * 4);
    state[12] = counter;
    state[13] = 0;
    state[14] = load32_le(nonce8);
    state[15] = load32_le(nonce8 + 4);

    for (size_t i = 0; i < len; i += 64) {
        chacha20_block(block, state);
        for (int j = 0; j < 16; j++)
            store32_le(keystream + j * 4, block[j]);

        size_t chunk = (len - i < 64) ? (len - i) : 64;
        for (size_t j = 0; j < chunk; j++)
            out[i + j] = in[i + j] ^ keystream[j];

        state[12]++;
    }

    fossil_cryptic_util_wipe(state, sizeof(state));
    fossil_cryptic_util_wipe(block, sizeof(block));
    fossil_cryptic_util_wipe(keystream, sizeof(keystream));
}

/* ---------- Poly1305 ---------- */

typedef struct {
    uint32_t v[5];
} poly1305_fe;

static void fe_from_bytes(poly1305_fe *h, const uint8_t s[16]) {
    uint32_t t0 = load32_le(s +  0);
    uint32_t t1 = load32_le(s +  4);
    uint32_t t2 = load32_le(s +  8);
    uint32_t t3 = load32_le(s + 12);

    h->v[0] =  t0                    & 0x3ffffff;
    h->v[1] = (t0 >> 26 | t1 <<  6)  & 0x3ffffff;
    h->v[2] = (t1 >> 20 | t2 << 12)  & 0x3ffffff;
    h->v[3] = (t2 >> 14 | t3 << 18)  & 0x3ffffff;
    h->v[4] =  t3 >> 8;
}

static void fe_freeze(uint8_t out[16], const poly1305_fe *h) {
    uint32_t h0 = h->v[0], h1 = h->v[1], h2 = h->v[2], h3 = h->v[3], h4 = h->v[4];
    uint32_t g0, g1, g2, g3, g4, b;

    /* fully carry */
    h1 += h0 >> 26; h0 &= 0x3ffffff;
    h2 += h1 >> 26; h1 &= 0x3ffffff;
    h3 += h2 >> 26; h2 &= 0x3ffffff;
    h4 += h3 >> 26; h3 &= 0x3ffffff;
    h0 += (h4 >> 26) * 5; h4 &= 0x3ffffff;
    h1 += h0 >> 26; h0 &= 0x3ffffff;

    /* compute h + -p */
    g0 = h0 + 5; b = g0 >> 26; g0 &= 0x3ffffff;
    g1 = h1 + b; b = g1 >> 26; g1 &= 0x3ffffff;
    g2 = h2 + b; b = g2 >> 26; g2 &= 0x3ffffff;
    g3 = h3 + b; b = g3 >> 26; g3 &= 0x3ffffff;
    g4 = h4 + b - (1UL << 26);

    /* select */
    b = (g4 >> 31) - 1;
    g0 &= b; g1 &= b; g2 &= b; g3 &= b; g4 &= b;
    b = ~b;
    h0 = (h0 & b) | g0;
    h1 = (h1 & b) | g1;
    h2 = (h2 & b) | g2;
    h3 = (h3 & b) | g3;
    h4 = (h4 & b) | g4;

    /* pack */
    uint32_t t0 = (h0      ) | (h1 << 26);
    uint32_t t1 = (h1 >>  6) | (h2 << 20);
    uint32_t t2 = (h2 >> 12) | (h3 << 14);
    uint32_t t3 = (h3 >> 18) | (h4 <<  8);
    store32_le(out +  0, t0);
    store32_le(out +  4, t1);
    store32_le(out +  8, t2);
    store32_le(out + 12, t3);
}

typedef struct {
    poly1305_fe r, h;
    uint32_t pad[4];
    uint8_t  buf[16];
    size_t   buf_len;
} poly1305_ctx;

static void poly1305_init(poly1305_ctx *st, const uint8_t key[32]) {
    memset(st, 0, sizeof(*st));
    fe_from_bytes(&st->r, key);
    /* clamp r */
    st->r.v[0] &= 0x3ffffff;
    st->r.v[1] &= 0x3ffff03;
    st->r.v[2] &= 0x3ffc0ff;
    st->r.v[3] &= 0x3f03fff;
    st->r.v[4] &= 0x00fffff;
    st->pad[0] = load32_le(key + 16);
    st->pad[1] = load32_le(key + 20);
    st->pad[2] = load32_le(key + 24);
    st->pad[3] = load32_le(key + 28);
}

static void poly1305_blocks(poly1305_ctx *st, const uint8_t *m, size_t nblocks, int final_bit) {
    const uint32_t r0 = st->r.v[0], r1 = st->r.v[1], r2 = st->r.v[2],
                   r3 = st->r.v[3], r4 = st->r.v[4];
    const uint32_t s1 = r1 * 5, s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5;
    uint32_t h0 = st->h.v[0], h1 = st->h.v[1], h2 = st->h.v[2],
             h3 = st->h.v[3], h4 = st->h.v[4];

    while (nblocks--) {
        uint32_t t0 = load32_le(m +  0);
        uint32_t t1 = load32_le(m +  4);
        uint32_t t2 = load32_le(m +  8);
        uint32_t t3 = load32_le(m + 12);

        h0 +=  t0                    & 0x3ffffff;
        h1 += (t0 >> 26 | t1 <<  6)  & 0x3ffffff;
        h2 += (t1 >> 20 | t2 << 12)  & 0x3ffffff;
        h3 += (t2 >> 14 | t3 << 18)  & 0x3ffffff;
        h4 += (t3 >>  8) | ((uint32_t)final_bit << 24);

        uint64_t d0 = (uint64_t)h0*r0 + (uint64_t)h1*s4 + (uint64_t)h2*s3 + (uint64_t)h3*s2 + (uint64_t)h4*s1;
        uint64_t d1 = (uint64_t)h0*r1 + (uint64_t)h1*r0 + (uint64_t)h2*s4 + (uint64_t)h3*s3 + (uint64_t)h4*s2;
        uint64_t d2 = (uint64_t)h0*r2 + (uint64_t)h1*r1 + (uint64_t)h2*r0 + (uint64_t)h3*s4 + (uint64_t)h4*s3;
        uint64_t d3 = (uint64_t)h0*r3 + (uint64_t)h1*r2 + (uint64_t)h2*r1 + (uint64_t)h3*r0 + (uint64_t)h4*s4;
        uint64_t d4 = (uint64_t)h0*r4 + (uint64_t)h1*r3 + (uint64_t)h2*r2 + (uint64_t)h3*r1 + (uint64_t)h4*r0;

        h0 = (uint32_t)d0 & 0x3ffffff; d1 += d0 >> 26;
        h1 = (uint32_t)d1 & 0x3ffffff; d2 += d1 >> 26;
        h2 = (uint32_t)d2 & 0x3ffffff; d3 += d2 >> 26;
        h3 = (uint32_t)d3 & 0x3ffffff; d4 += d3 >> 26;
        h4 = (uint32_t)d4 & 0x3ffffff;
        h0 += (uint32_t)(d4 >> 26) * 5;
        h1 += h0 >> 26; h0 &= 0x3ffffff;

        m += 16;
    }
    st->h.v[0] = h0; st->h.v[1] = h1; st->h.v[2] = h2;
    st->h.v[3] = h3; st->h.v[4] = h4;
}

static void poly1305_update(poly1305_ctx *st, const uint8_t *m, size_t n) {
    if (st->buf_len) {
        size_t want = 16 - st->buf_len;
        if (want > n) want = n;
        memcpy(st->buf + st->buf_len, m, want);
        st->buf_len += want;
        m += want; n -= want;
        if (st->buf_len == 16) {
            poly1305_blocks(st, st->buf, 1, 1);
            st->buf_len = 0;
        }
    }
    if (n >= 16) {
        size_t nblocks = n / 16;
        poly1305_blocks(st, m, nblocks, 1);
        m += nblocks * 16;
        n -= nblocks * 16;
    }
    if (n) {
        memcpy(st->buf, m, n);
        st->buf_len = n;
    }
}

static void poly1305_finish(poly1305_ctx *st, uint8_t mac[16]) {
    if (st->buf_len) {
        st->buf[st->buf_len] = 1;
        memset(st->buf + st->buf_len + 1, 0, 15 - st->buf_len);
        poly1305_blocks(st, st->buf, 1, 0);
    }

    uint8_t hbytes[16];
    fe_freeze(hbytes, &st->h);

    uint64_t c = 0;
    uint32_t t[4];
    for (int i = 0; i < 4; i++) {
        c += (uint64_t)load32_le(hbytes + i * 4) + st->pad[i];
        t[i] = (uint32_t)c;
        c >>= 32;
    }
    for (int i = 0; i < 4; i++)
        store32_le(mac + i * 4, t[i]);

    fossil_cryptic_util_wipe(st, sizeof(*st));
}

/* ---------- AEAD construction ---------- */

static void poly1305_pad16(poly1305_ctx *st, size_t len) {
    size_t rem = len & 15;
    if (rem) {
        uint8_t zeros[16] = {0};
        poly1305_update(st, zeros, 16 - rem);
    }
}

static void aead_mac(uint8_t tag[16],
                     const uint8_t otk[32],
                     const uint8_t *ad, size_t ad_len,
                     const uint8_t *ct, size_t ct_len) {
    poly1305_ctx st;
    uint8_t lens[16];

    poly1305_init(&st, otk);
    if (ad_len) {
        poly1305_update(&st, ad, ad_len);
        poly1305_pad16(&st, ad_len);
    }
    if (ct_len) {
        poly1305_update(&st, ct, ct_len);
        poly1305_pad16(&st, ct_len);
    }
    /* lengths as 64-bit little-endian */
    memset(lens, 0, 16);
    store32_le(lens + 0, (uint32_t)ad_len);
    store32_le(lens + 4, (uint32_t)((uint64_t)ad_len >> 32));
    store32_le(lens + 8, (uint32_t)ct_len);
    store32_le(lens +12, (uint32_t)((uint64_t)ct_len >> 32));
    poly1305_update(&st, lens, 16);
    poly1305_finish(&st, tag);
}

/* ---------- Public API ---------- */

int fossil_cryptic_aead_encrypt(
    uint8_t *ciphertext,
    const uint8_t key[32],
    const uint8_t nonce[24],
    const uint8_t *ad, size_t ad_len,
    const uint8_t *plaintext, size_t text_len)
{
    if (!ciphertext || !key || !nonce) return -1;
    if (text_len && !plaintext) return -1;
    if (ad_len && !ad) return -1;

    uint8_t subkey[32];
    uint8_t otk[64];
    uint8_t tag[16];

    /* XChaCha20: derive subkey from first 16 bytes of nonce */
    hchacha20(subkey, key, nonce);

    /* Poly1305 one-time key = first 32 bytes of keystream at counter 0 */
    memset(otk, 0, sizeof(otk));
    chacha20_xor(otk, otk, 64, subkey, nonce + 16, 0);

    /* Encrypt with counter starting at 1 */
    if (text_len)
        chacha20_xor(ciphertext, plaintext, text_len, subkey, nonce + 16, 1);

    aead_mac(tag, otk, ad, ad_len, ciphertext, text_len);
    memcpy(ciphertext + text_len, tag, 16);

    fossil_cryptic_util_wipe(subkey, sizeof(subkey));
    fossil_cryptic_util_wipe(otk, sizeof(otk));
    fossil_cryptic_util_wipe(tag, sizeof(tag));
    return 0;
}

int fossil_cryptic_aead_decrypt(
    uint8_t *plaintext,
    const uint8_t key[32],
    const uint8_t nonce[24],
    const uint8_t *ad, size_t ad_len,
    const uint8_t *ciphertext, size_t ciphertext_len)
{
    if (!plaintext || !key || !nonce || !ciphertext) return -1;
    if (ad_len && !ad) return -1;
    if (ciphertext_len < 16) return -1;

    size_t text_len = ciphertext_len - 16;

    uint8_t subkey[32];
    uint8_t otk[64];
    uint8_t expect[16];
    const uint8_t *tag = ciphertext + text_len;

    hchacha20(subkey, key, nonce);

    memset(otk, 0, sizeof(otk));
    chacha20_xor(otk, otk, 64, subkey, nonce + 16, 0);

    aead_mac(expect, otk, ad, ad_len, ciphertext, text_len);
    int rc = fossil_cryptic_util_verify16(tag, expect);

    if (rc == 0 && text_len)
        chacha20_xor(plaintext, ciphertext, text_len, subkey, nonce + 16, 1);

    fossil_cryptic_util_wipe(subkey, sizeof(subkey));
    fossil_cryptic_util_wipe(otk, sizeof(otk));
    fossil_cryptic_util_wipe(expect, sizeof(expect));
    return rc;
}
