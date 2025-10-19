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
#include "fossil/cryptic/auth.h"
#include "fossil/cryptic/hash.h"
#include "fossil/cryptic/dencrypt.h"
#include "fossil/cryptic/encrypt.h"
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

/* ---------------------------
 * secure_zero (decrypt side)
 * --------------------------*/
void fossil_cryptic_dec_secure_zero(void *p, size_t n) {
    if (!p || n == 0) return;
    volatile uint8_t *v = (volatile uint8_t *)p;
    while (n--) *v++ = 0;
}

/* ---------------------------
 * ChaCha20-CTR wrapper (decrypt side)
 * --------------------------*/
void fossil_cryptic_dec_chacha20_ctr_xor(const uint8_t key[32], const uint8_t nonce[12], uint32_t counter, const uint8_t *in, uint8_t *out, size_t len) {
    fossil_cryptic_auth_chacha20_xor(key, nonce, counter, in, out, len);
}

/* ---------------------------
 * ChaCha20-Poly1305 AEAD wrapper (decrypt side)
 * --------------------------*/
int fossil_cryptic_dec_chacha20_poly1305_decrypt(const uint8_t key[32], const uint8_t nonce[12], const uint8_t *aad, size_t aad_len, const uint8_t *ciphertext, size_t ct_len, uint8_t *plaintext, const uint8_t tag[16]) {
    return fossil_cryptic_auth_chacha20_poly1305_decrypt(key, nonce, aad, aad_len, ciphertext, ct_len, plaintext, tag);
}

/* ---------------------------
 * AES-CTR + HMAC-SHA256 (Verify-then-Decrypt)
 * --------------------------*/
int fossil_cryptic_dec_aes128_ctr_verify_then_decrypt_hmac_sha256(const uint8_t key[16], const uint8_t iv[16], const uint8_t *aad, size_t aad_len, const uint8_t *ciphertext, size_t ct_len, uint8_t *plaintext, const uint8_t mac_in[32]) {
    return fossil_cryptic_enc_aes128_ctr_verify_then_decrypt_hmac_sha256(key, iv, aad, aad_len, ciphertext, ct_len, plaintext, mac_in);
}
