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
#ifndef FOSSIL_CRYPTIC_CHACHA_H
#define FOSSIL_CRYPTIC_CHACHA_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Performs ChaCha20 encryption/decryption on the input data.
 * 
 * @param out Pointer to the output buffer where the result will be stored.
 * @param in Pointer to the input data to be encrypted/decrypted.
 * @param len Length of the input data in bytes.
 * @param key Pointer to the 32-byte encryption key.
 * @param nonce Pointer to the 12-byte nonce (number used once).
 * @param counter Initial block counter value.
 * 
 * @return 0 on success, non-zero on failure.
 * 
 * @note This function is intended for use in C environments. For C++ code, use fossil::cryptic::Chacha::xor_stream instead.
 */
int fossil_cryptic_chacha20_xor(
    uint8_t *out,
    const uint8_t *in, size_t len,
    const uint8_t key[32],
    const uint8_t nonce[12],
    uint32_t counter);

/** 
 * @brief Computes the Poly1305 MAC (Message Authentication Code) for the given message.
 * 
 * @param tag Pointer to a 16-byte buffer where the computed MAC will be stored.
 * @param msg Pointer to the input message data.
 * @param msg_len Length of the input message in bytes.
 * @param key Pointer to the 32-byte key used for MAC computation.
 * 
 * @return 0 on success, non-zero on failure.
 * 
 * @note This function is intended for use in C environments. For C++ code, use fossil::cryptic::Chacha::poly1305 instead.
 */
int fossil_cryptic_poly1305(
    uint8_t tag[16],
    const uint8_t *msg, size_t msg_len,
    const uint8_t key[32]);

/**
 * @brief Encrypts plaintext using the ChaCha20-Poly1305 AEAD (Authenticated Encryption with Associated Data) scheme.
 *
 * @param ciphertext Pointer to the output buffer where the ciphertext will be stored.
 * @param key Pointer to the 32-byte encryption key.
 * @param nonce Pointer to the 12-byte nonce (number used once).
 * @param ad Pointer to the associated data (AD) to be authenticated but not encrypted.
 * @param ad_len Length of the associated data in bytes.
 * @param plaintext Pointer to the input plaintext data to be encrypted.
 * @param text_len Length of the plaintext data in bytes.
 *
 * @return 0 on success, non-zero on failure.
 *
 * @note This function is intended for use in C environments. For C++ code, use fossil::cryptic::Chacha::encrypt instead.
 */
int fossil_cryptic_chacha20_poly1305_encrypt(
    uint8_t *ciphertext,
    const uint8_t key[32],
    const uint8_t nonce[12],
    const uint8_t *ad, size_t ad_len,
    const uint8_t *plaintext, size_t text_len);

/**
 * @brief Decrypts ciphertext using the ChaCha20-Poly1305 AEAD (Authenticated Encryption with Associated Data) scheme.
 *
 * @param plaintext Pointer to the output buffer where the decrypted plaintext will be stored.
 * @param key Pointer to the 32-byte decryption key.
 * @param nonce Pointer to the 12-byte nonce (number used once).
 * @param ad Pointer to the associated data (AD) that was authenticated during encryption.
 * @param ad_len Length of the associated data in bytes.
 * @param ciphertext Pointer to the input ciphertext data to be decrypted.
 * @param text_len Length of the ciphertext data in bytes.
 *
 * @return 0 on success, non-zero on failure.
 * 
 * @note This function is intended for use in C environments. For C++ code, use fossil::cryptic::Chacha::decrypt instead.
 */
int fossil_cryptic_chacha20_poly1305_decrypt(
    uint8_t *plaintext,
    const uint8_t key[32],
    const uint8_t nonce[12],
    const uint8_t *ad, size_t ad_len,
    const uint8_t *ciphertext, size_t text_len);

#ifdef __cplusplus
}
namespace fossil::cryptic {

    class Chacha {
    public:
        /**
         * @brief Performs ChaCha20 encryption/decryption on the input data.
         *
         * @param out Pointer to the output buffer where the result will be stored.
         * @param in Pointer to the input data to be encrypted/decrypted.
         * @param len Length of the input data in bytes.
         * @param key Pointer to the 32-byte encryption key.
         * @param nonce Pointer to the 12-byte nonce (number used once).
         * @param counter Initial block counter value.
         *
         * @return 0 on success, non-zero on failure.
         */
        static int xor_stream(uint8_t *out, const uint8_t *in, size_t len,
                            const uint8_t key[32], const uint8_t nonce[12], uint32_t counter) {
            return fossil_cryptic_chacha20_xor(out, in, len, key, nonce, counter);
        }

        /**
         * @brief Computes the Poly1305 MAC (Message Authentication Code) for the given message.
         *
         * @param tag Pointer to a 16-byte buffer where the computed MAC will be stored.
         * @param msg Pointer to the input message data.
         * @param msg_len Length of the input message in bytes.
         * @param key Pointer to the 32-byte key used for MAC computation.
         *
         * @return 0 on success, non-zero on failure.
         */
        static int poly1305(uint8_t tag[16], const uint8_t *msg, size_t len, const uint8_t key[32]) {
            return fossil_cryptic_poly1305(tag, msg, len, key);
        }

        /**
         * @brief Encrypts plaintext using the ChaCha20-Poly1305 AEAD (Authenticated Encryption with Associated Data) scheme.
         *
         * @param ct Pointer to the output buffer where the ciphertext will be stored.
         * @param key Pointer to the 32-byte encryption key.
         * @param nonce Pointer to the 12-byte nonce (number used once).
         * @param ad Pointer to the associated data (AD) to be authenticated but not encrypted.
         * @param ad_len Length of the associated data in bytes.
         * @param pt Pointer to the input plaintext data to be encrypted.
         * @param pt_len Length of the plaintext data in bytes.
         *
         * @return 0 on success, non-zero on failure.
         */
        static int encrypt(uint8_t *ct, const uint8_t key[32], const uint8_t nonce[12],
                        const uint8_t *ad, size_t ad_len,
                        const uint8_t *pt, size_t pt_len) {
            return fossil_cryptic_chacha20_poly1305_encrypt(ct, key, nonce, ad, ad_len, pt, pt_len);
        }

        /**
         * @brief Decrypts ciphertext using the ChaCha20-Poly1305 AEAD (Authenticated Encryption with Associated Data) scheme.
         *
         * @param pt Pointer to the output buffer where the decrypted plaintext will be stored.
         * @param key Pointer to the 32-byte decryption key.
         * @param nonce Pointer to the 12-byte nonce (number used once).
         * @param ad Pointer to the associated data (AD) that was authenticated during encryption.
         * @param ad_len Length of the associated data in bytes.
         * @param ct Pointer to the input ciphertext data to be decrypted.
         * @param ct_len Length of the ciphertext data in bytes.
         *
         * @return 0 on success, non-zero on failure.
         */
        static int decrypt(uint8_t *pt, const uint8_t key[32], const uint8_t nonce[12],
                        const uint8_t *ad, size_t ad_len,
                        const uint8_t *ct, size_t ct_len) {
            return fossil_cryptic_chacha20_poly1305_decrypt(pt, key, nonce, ad, ad_len, ct, ct_len);
        }
    };

} // namespace cryptic::fossil

#endif

#endif /* FOSSIL_CRYPTIC_CHACHA_H */
