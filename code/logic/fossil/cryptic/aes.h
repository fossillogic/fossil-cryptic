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
#ifndef FOSSIL_CRYPTIC_AES_H
#define FOSSIL_CRYPTIC_AES_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Encrypt plaintext using AES-256-GCM with a 12-byte nonce and append a 16-byte authentication tag to ciphertext.
 * The ciphertext buffer must hold at least text_len + 16 bytes.
 * 
 * @param ciphertext Pointer to the buffer where the encrypted data will be stored.
 * @param key Pointer to the 32-byte encryption key.
 * @param nonce Pointer to the 12-byte nonce.
 * @param ad Pointer to the additional authenticated data (AAD).
 * @param ad_len Length of the additional authenticated data.
 * @param plaintext Pointer to the plaintext data to be encrypted.
 * @param text_len Length of the plaintext data.
 * 
 * @return 0 on success or -1 on invalid arguments.
 */
int fossil_cryptic_aes_gcm_encrypt(
    uint8_t *ciphertext,
    const uint8_t key[32],
    const uint8_t nonce[12],
    const uint8_t *ad, size_t ad_len,
    const uint8_t *plaintext, size_t text_len
);

/** Decrypt ciphertext using AES-256-GCM with a 12-byte nonce and its trailing 16-byte authentication tag.
 * text_len is the encrypted payload length, excluding the tag.
 *
 * @param plaintext Pointer to the buffer where the decrypted data will be stored.
 * @param key Pointer to the 32-byte decryption key.
 * @param nonce Pointer to the 12-byte nonce.
 * @param ad Pointer to the additional authenticated data (AAD).
 * @param ad_len Length of the additional authenticated data.
 * @param ciphertext Pointer to the ciphertext data to be decrypted.
 * @param text_len Length of the ciphertext data, excluding the tag.
 *
 * @return 0 on success or -1 on invalid arguments/authentication failure.
 */
int fossil_cryptic_aes_gcm_decrypt(
    uint8_t *plaintext,
    const uint8_t key[32],
    const uint8_t nonce[12],
    const uint8_t *ad, size_t ad_len,
    const uint8_t *ciphertext, size_t text_len
);

#ifdef __cplusplus
}
namespace fossil {

    namespace cryptic {

        /**
         * @class Aes
         * @brief C++ wrapper for authenticated encryption logic in the Fossil Cryptic project.
         *
         * The Aes class provides C++-friendly wrappers for the C API.
         *
         * Usage example:
         * @code
         *     uint8_t ciphertext[sizeof(plaintext) + 16];
         *     fossil::cryptic::Aes::encrypt(ciphertext, key, nonce, nullptr, 0,
         *                                    plaintext, sizeof(plaintext));
         * @endcode
         *
         * @note
         * This class is intended for use in C++ environments only. For C code,
         * use fossil_cryptic_aes_gcm_encrypt and fossil_cryptic_aes_gcm_decrypt directly.
         */
        class Aes {
        public:
            /**
             * @brief Encrypts the given plaintext with the provided key, nonce, and additional authenticated data (AAD).
             *
             * @param ciphertext Pointer to the output buffer, which must hold at least text_len + 16 bytes.
             * @param key Pointer to the 32-byte encryption key.
             * @param nonce Pointer to the 12-byte nonce.
             * @param ad Pointer to the additional authenticated data (AAD).
             * @param ad_len Length of the additional authenticated data.
             * @param plaintext Pointer to the plaintext data to be encrypted.
             * @param text_len Length of the plaintext data.
             *
             * @return 0 on success or -1 on invalid arguments. The 16-byte authentication tag is
             *         appended to the ciphertext.
             */
            static int encrypt(
                uint8_t *ciphertext,
                const uint8_t key[32],
                const uint8_t nonce[12],
                const uint8_t *ad, size_t ad_len,
                const uint8_t *plaintext, size_t text_len)
            {
                return fossil_cryptic_aes_gcm_encrypt(
                    ciphertext, key, nonce, ad, ad_len, plaintext, text_len);
            }

            /**
             * @brief Decrypts the given ciphertext with the provided key, nonce, and additional authenticated data (AAD).
             *
             * @param plaintext Pointer to the buffer where the decrypted data will be stored.
             * @param key Pointer to the 32-byte decryption key.
             * @param nonce Pointer to the 12-byte nonce.
             * @param ad Pointer to the additional authenticated data (AAD).
             * @param ad_len Length of the additional authenticated data.
             * @param ciphertext Pointer to the ciphertext followed by its 16-byte authentication tag.
             * @param text_len Length of the encrypted payload, excluding the tag.
             *
             * @return 0 on success or -1 on invalid arguments/authentication failure.
             */
            static int decrypt(
                uint8_t *plaintext,
                const uint8_t key[32],
                const uint8_t nonce[12],
                const uint8_t *ad, size_t ad_len,
                const uint8_t *ciphertext, size_t text_len)
            {
                return fossil_cryptic_aes_gcm_decrypt(
                    plaintext, key, nonce, ad, ad_len, ciphertext, text_len);
            }
        };

    } // namespace cryptic

} // namespace fossil

#endif

#endif /* FOSSIL_CRYPTIC_AEAD_H */
