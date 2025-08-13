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
#include "fossil/cryptic/enc.h"
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

/* ---------------------------
 * secure_zero
 * --------------------------*/
void fossil_cryptic_enc_secure_zero(void *p, size_t n) {
    if (!p || n == 0) return;
    volatile uint8_t *v = (volatile uint8_t *)p;
    while (n--) *v++ = 0;
}

/* ---------------------------
 * ChaCha20-CTR wrapper
 * --------------------------*/
void fossil_cryptic_enc_chacha20_ctr_xor(const uint8_t key[32], const uint8_t nonce[12], uint32_t counter, const uint8_t *in, uint8_t *out, size_t len) {
    fossil_cryptic_auth_chacha20_xor(key, nonce, counter, in, out, len);
}

/* ---------------------------
 * ChaCha20-Poly1305 AEAD wrappers (thin)
 * --------------------------*/
void fossil_cryptic_enc_chacha20_poly1305_encrypt(const uint8_t key[32], const uint8_t nonce[12], const uint8_t *aad, size_t aad_len, const uint8_t *plaintext, size_t pt_len, uint8_t *ciphertext, uint8_t tag[16]) {
    fossil_cryptic_auth_chacha20_poly1305_encrypt(key, nonce, aad, aad_len, plaintext, pt_len, ciphertext, tag);
}

int fossil_cryptic_enc_chacha20_poly1305_decrypt(const uint8_t key[32], const uint8_t nonce[12], const uint8_t *aad, size_t aad_len, const uint8_t *ciphertext, size_t ct_len, uint8_t *plaintext, const uint8_t tag[16]) {
    return fossil_cryptic_auth_chacha20_poly1305_decrypt(key, nonce, aad, aad_len, ciphertext, ct_len, plaintext, tag);
}

/* ---------------------------
 * Small AES-128 (encryption-only) for CTR mode
 * - Compact, readable implementation of AES-128 block encrypt
 * - Not optimized; suitable for correctness and portability
 *
 * If you want AES-256 or high-performance AES, we can add those later.
 * --------------------------*/

/* AES S-box */
static const uint8_t aes_sbox[256] = {
  /* 0x00..0x0f */ 0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
  /* 0x10..0x1f */ 0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
  /* 0x20..0x2f */ 0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
  /* 0x30..0x3f */ 0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
  /* 0x40..0x4f */ 0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
  /* 0x50..0x5f */ 0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
  /* 0x60..0x6f */ 0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
  /* 0x70..0x7f */ 0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
  /* 0x80..0x8f */ 0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
  /* 0x90..0x9f */ 0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
  /* 0xa0..0xaf */ 0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
  /* 0xb0..0xbf */ 0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
  /* 0xc0..0xcf */ 0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
  /* 0xd0..0xdf */ 0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
  /* 0xe0..0xef */ 0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
  /* 0xf0..0xff */ 0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

/* For brevity I include a compact key expansion/encrypt block suitable for AES-128.
   This is not performance-tuned but correct for CTR usage.*/

/* multiply in GF(2^8) by 2, used by MixColumns if we were to implement - omitted for CTR which uses AES block only */
static uint8_t xtime(uint8_t x) {
    return (uint8_t)((x << 1) ^ ((x & 0x80) ? 0x1b : 0x00));
}

/* Expand 128-bit key into 11 round keys (AES-128): 11 * 16 = 176 bytes */
static void aes128_key_expansion(const uint8_t key[16], uint8_t round_keys[176]) {
    /* Basic implementation of Rijndael key schedule */
    memcpy(round_keys, key, 16);
    uint8_t rcon = 1;
    uint8_t temp[4];
    for (int i = 16; i < 176; i += 4) {
        memcpy(temp, round_keys + i - 4, 4);
        if (i % 16 == 0) {
            /* rotate */
            uint8_t t = temp[0];
            temp[0] = temp[1]; temp[1] = temp[2]; temp[2] = temp[3]; temp[3] = t;
            /* sbox */
            temp[0] = aes_sbox[temp[0]];
            temp[1] = aes_sbox[temp[1]];
            temp[2] = aes_sbox[temp[2]];
            temp[3] = aes_sbox[temp[3]];
            temp[0] ^= rcon;
            rcon = (uint8_t)((rcon << 1) ^ ((rcon & 0x80) ? 0x1b : 0x00));
        }
        for (int j = 0; j < 4; ++j) {
            round_keys[i + j] = round_keys[i - 16 + j] ^ temp[j];
        }
    }
}

/* SubBytes + ShiftRows + MixColumns (MixColumns omitted when doing only block encryption via Sub+Shift+AddRoundKey and MixColumns for all rounds except last)
   For correctness, we implement full round operations. */

/* AES block encrypt (128-bit) */
static void aes128_encrypt_block(const uint8_t round_keys[176], const uint8_t in[16], uint8_t out[16]) {
    uint8_t state[16];
    memcpy(state, in, 16);

    /* AddRoundKey(0) */
    for (int i = 0; i < 16; ++i) state[i] ^= round_keys[i];

    /* 9 full rounds */
    for (int round = 1; round <= 9; ++round) {
        /* SubBytes */
        for (int i = 0; i < 16; ++i) state[i] = aes_sbox[state[i]];
        /* ShiftRows */
        uint8_t tmp[16];
        tmp[0] = state[0];
        tmp[1] = state[5];
        tmp[2] = state[10];
        tmp[3] = state[15];
        tmp[4] = state[4];
        tmp[5] = state[9];
        tmp[6] = state[14];
        tmp[7] = state[3];
        tmp[8] = state[8];
        tmp[9] = state[13];
        tmp[10] = state[2];
        tmp[11] = state[7];
        tmp[12] = state[12];
        tmp[13] = state[1];
        tmp[14] = state[6];
        tmp[15] = state[11];
        /* MixColumns (naive) */
        for (int c = 0; c < 4; ++c) {
            int col = c * 4;
            uint8_t a0 = tmp[col + 0];
            uint8_t a1 = tmp[col + 1];
            uint8_t a2 = tmp[col + 2];
            uint8_t a3 = tmp[col + 3];
            uint8_t r0 = (uint8_t)(xtime(a0) ^ (a1 ^ xtime(a1)) ^ a2 ^ a3);
            uint8_t r1 = (uint8_t)(a0 ^ xtime(a1) ^ (a2 ^ xtime(a2)) ^ a3);
            uint8_t r2 = (uint8_t)(a0 ^ a1 ^ xtime(a2) ^ (a3 ^ xtime(a3)));
            uint8_t r3 = (uint8_t)((a0 ^ xtime(a0)) ^ a1 ^ a2 ^ xtime(a3));
            state[col + 0] = r0;
            state[col + 1] = r1;
            state[col + 2] = r2;
            state[col + 3] = r3;
        }
        /* AddRoundKey */
        const uint8_t *rk = round_keys + round * 16;
        for (int i = 0; i < 16; ++i) state[i] ^= rk[i];
    }

    /* final round (SubBytes + ShiftRows + AddRoundKey) */
    for (int i = 0; i < 16; ++i) state[i] = aes_sbox[state[i]];
    uint8_t tmp2[16];
    tmp2[0] = state[0];
    tmp2[1] = state[5];
    tmp2[2] = state[10];
    tmp2[3] = state[15];
    tmp2[4] = state[4];
    tmp2[5] = state[9];
    tmp2[6] = state[14];
    tmp2[7] = state[3];
    tmp2[8] = state[8];
    tmp2[9] = state[13];
    tmp2[10] = state[2];
    tmp2[11] = state[7];
    tmp2[12] = state[12];
    tmp2[13] = state[1];
    tmp2[14] = state[6];
    tmp2[15] = state[11];

    const uint8_t *rkf = round_keys + 160; /* last round key */
    for (int i = 0; i < 16; ++i) out[i] = tmp2[i] ^ rkf[i];
}

/* AES-CTR: increment 128-bit counter (little-endian) */
static void aes128_ctr_incr(uint8_t counter[16]) {
    for (int i = 15; i >= 0; --i) {
        if (++counter[i]) break;
    }
}

void fossil_cryptic_enc_aes128_ctr_encrypt_then_mac_hmac_sha256(const uint8_t key[16], const uint8_t iv[16], const uint8_t *aad, size_t aad_len, const uint8_t *plaintext, size_t pt_len, uint8_t *ciphertext, uint8_t mac_out[32]) {
    /* Expand key */
    uint8_t round_keys[176];
    aes128_key_expansion(key, round_keys);

    /* copy IV to counter */
    uint8_t counter[16];
    memcpy(counter, iv, 16);

    /* encrypt */
    size_t pos = 0;
    uint8_t block[16];
    while (pos < pt_len) {
        aes128_encrypt_block(round_keys, counter, block);
        size_t chunk = (pt_len - pos) < 16 ? (pt_len - pos) : 16;
        for (size_t i = 0; i < chunk; ++i) {
            ciphertext[pos + i] = plaintext[pos + i] ^ block[i];
        }
        pos += chunk;
        aes128_ctr_incr(counter);
    }

    /* compute HMAC-SHA256 over aad || ciphertext || len(aad) || len(ct) (64-bit BE each part lengths) */
    /* we'll compose a small length-block in big-endian as specified */
    uint8_t len_block[16];
    /* lengths in big-endian 64-bit to match many KDF/AAD conventions; choose consistent endianness for your protocol */
    for (int i = 0; i < 8; ++i) {
        len_block[i] = (uint8_t)((aad_len >> (56 - 8*i)) & 0xFF);
        len_block[8 + i] = (uint8_t)((pt_len >> (56 - 8*i)) & 0xFF);
    }

    /* HMAC key selection: re-use AES key? NO: user should provide separate key in real systems.
       For simplicity we derive an HMAC key by hashing the AES key — but best practice is to use separate keys. */
    uint8_t hmac_key[32];
    fossil_cryptic_hash_sha256(key, 16, hmac_key);

    /* compute HMAC-SHA256 */
    fossil_cryptic_auth_hmac_sha256(hmac_key, 32, aad, aad_len, mac_out); /* start with aad */
    /* update HMAC: over ciphertext and length block - but our simple HMAC wrapper expects single message, so compose a buffer */
    /* We'll create small temporary buffer if needed */
    if (pt_len > 0) {
        /* because fossil_cryptic_auth_hmac_sha256 is one-shot, compute HMAC over concatenated data */
        /* This approach: compute HMAC(key, aad || ciphertext || len_block) by building a small buffer if sizes small, else stream via inner functions (but we only have one-shot) */
        /* For simplicity: allocate on stack up to reasonable size or process in pieces by using streaming HMAC implementation - which we don't have. So here we build a dynamic path for large ciphertexts. */
        /* Simple approach: if total <= 4096 do on-stack concat, else use temp buffer via malloc (portable) */
        size_t total_len = aad_len + pt_len + 16;
        uint8_t *tmp = NULL;
        if (total_len <= 4096) {
            uint8_t stackbuf[4096];
            size_t off = 0;
            if (aad_len) { memcpy(stackbuf + off, aad, aad_len); off += aad_len; }
            memcpy(stackbuf + off, ciphertext, pt_len); off += pt_len;
            memcpy(stackbuf + off, len_block, 16); off += 16;
            fossil_cryptic_auth_hmac_sha256(hmac_key, 32, stackbuf, off, mac_out);
            fossil_cryptic_enc_secure_zero(stackbuf, off);
        } else {
            tmp = (uint8_t*)malloc(total_len);
            if (!tmp) {
                memset(mac_out, 0, 32);
                fossil_cryptic_enc_secure_zero(hmac_key, sizeof(hmac_key));
                return;
            }
            size_t off = 0;
            if (aad_len) { memcpy(tmp + off, aad, aad_len); off += aad_len; }
            memcpy(tmp + off, ciphertext, pt_len); off += pt_len;
            memcpy(tmp + off, len_block, 16); off += 16;
            fossil_cryptic_auth_hmac_sha256(hmac_key, 32, tmp, off, mac_out);
            fossil_cryptic_enc_secure_zero(tmp, total_len);
            free(tmp);
        }
    } else {
        /* no ciphertext - HMAC over aad || len_block */
        size_t total_len = aad_len + 16;
        uint8_t *tmp = NULL;
        if (total_len <= 4096) {
            uint8_t stackbuf[4096];
            size_t off = 0;
            if (aad_len) { memcpy(stackbuf + off, aad, aad_len); off += aad_len; }
            memcpy(stackbuf + off, len_block, 16); off += 16;
            fossil_cryptic_auth_hmac_sha256(hmac_key, 32, stackbuf, off, mac_out);
            fossil_cryptic_enc_secure_zero(stackbuf, off);
        } else {
            tmp = (uint8_t*)malloc(total_len);
            if (!tmp) {
                memset(mac_out, 0, 32);
                fossil_cryptic_enc_secure_zero(hmac_key, sizeof(hmac_key));
                return;
            }
            size_t off = 0;
            if (aad_len) { memcpy(tmp + off, aad, aad_len); off += aad_len; }
            memcpy(tmp + off, len_block, 16); off += 16;
            fossil_cryptic_auth_hmac_sha256(hmac_key, 32, tmp, off, mac_out);
            fossil_cryptic_enc_secure_zero(tmp, total_len);
            free(tmp);
        }
    }

    /* wipe sensitive */
    fossil_cryptic_enc_secure_zero(hmac_key, sizeof(hmac_key));
    fossil_cryptic_enc_secure_zero(round_keys, sizeof(round_keys));
    fossil_cryptic_enc_secure_zero(block, sizeof(block));
}

int fossil_cryptic_enc_aes128_ctr_verify_then_decrypt_hmac_sha256(const uint8_t key[16], const uint8_t iv[16], const uint8_t *aad, size_t aad_len, const uint8_t *ciphertext, size_t ct_len, uint8_t *plaintext, const uint8_t mac_in[32]) {
    uint8_t expected_mac[32];
    /* Decrypt-then-MAC? No — we must compute MAC over aad||ciphertext||lengths before decrypting */
    /* We can compute expected_mac by re-encrypting with a temporary buffer to avoid modifying ciphertext; but HMAC is computed over ciphertext, so no decrypt required. */
    /* Build ciphertext copy if necessary, but we already have ciphertext. So recompute MAC exactly as in encrypt_then_mac. */
    /* Derive hmac_key as in encryption (same derivation) */
    uint8_t hmac_key[32];
    fossil_cryptic_hash_sha256(key, 16, hmac_key);

    size_t total_len = aad_len + ct_len + 16;
    uint8_t *tmp = NULL;
    if (total_len <= 4096) {
        uint8_t stackbuf[4096];
        size_t off = 0;
        if (aad_len) { memcpy(stackbuf + off, aad, aad_len); off += aad_len; }
        memcpy(stackbuf + off, ciphertext, ct_len); off += ct_len;
        /* lengths in big-endian again */
        uint8_t len_block[16];
        for (int i = 0; i < 8; ++i) {
            len_block[i]     = (uint8_t)((aad_len >> (56 - 8*i)) & 0xFF);
            len_block[8 + i] = (uint8_t)((ct_len >> (56 - 8*i)) & 0xFF);
        }
        memcpy(stackbuf + off, len_block, 16); off += 16;
        fossil_cryptic_auth_hmac_sha256(hmac_key, 32, stackbuf, off, expected_mac);
        fossil_cryptic_enc_secure_zero(stackbuf, off);
    } else {
        tmp = (uint8_t*)malloc(total_len);
        if (!tmp) { fossil_cryptic_enc_secure_zero(hmac_key, sizeof(hmac_key)); return 0; }
        size_t off = 0;
        if (aad_len) { memcpy(tmp + off, aad, aad_len); off += aad_len; }
        memcpy(tmp + off, ciphertext, ct_len); off += ct_len;
        uint8_t len_block[16];
        for (int i = 0; i < 8; ++i) {
            len_block[i]     = (uint8_t)((aad_len >> (56 - 8*i)) & 0xFF);
            len_block[8 + i] = (uint8_t)((ct_len >> (56 - 8*i)) & 0xFF);
        }
        memcpy(tmp + off, len_block, 16); off += 16;
        fossil_cryptic_auth_hmac_sha256(hmac_key, 32, tmp, off, expected_mac);
        fossil_cryptic_enc_secure_zero(tmp, total_len);
        free(tmp);
    }

    int ok = fossil_cryptic_auth_consttime_equal(expected_mac, mac_in, 32);
    fossil_cryptic_enc_secure_zero(hmac_key, sizeof(hmac_key));
    if (!ok) return 0;

    /* MAC valid - decrypt ciphertext into plaintext */
    uint8_t round_keys[176];
    aes128_key_expansion(key, round_keys);
    uint8_t counter[16];
    memcpy(counter, iv, 16);
    size_t pos = 0;
    uint8_t block[16];
    while (pos < ct_len) {
        aes128_encrypt_block(round_keys, counter, block);
        size_t chunk = (ct_len - pos) < 16 ? (ct_len - pos) : 16;
        for (size_t i = 0; i < chunk; ++i) {
            plaintext[pos + i] = ciphertext[pos + i] ^ block[i];
        }
        pos += chunk;
        aes128_ctr_incr(counter);
    }

    /* wipe */
    fossil_cryptic_enc_secure_zero(round_keys, sizeof(round_keys));
    fossil_cryptic_enc_secure_zero(block, sizeof(block));
    fossil_cryptic_enc_secure_zero(expected_mac, sizeof(expected_mac));
    return 1;
}
