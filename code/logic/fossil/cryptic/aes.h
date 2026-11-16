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

/**
 * @brief Encrypt with AES-256-GCM.
 * 
 * @param ciphertext Pointer to the buffer where the encrypted data will be stored.
 * @param key Pointer to the 32-byte encryption key.
 * @param nonce Pointer to the 12-byte nonce.
 * @param ad Pointer to the additional authenticated data (AAD).
 * @param ad_len Length of the additional authenticated data.
 * @param plaintext Pointer to the plaintext data to be encrypted.
 * @param text_len Length of the plaintext data.
 * 
 * @return 0 on success, -1 on invalid arguments.
 * 
 * @note This function is intended for use in C environments. For C++ code, use fossil::cryptic::Aes::encrypt instead.
 */
int fossil_cryptic_aes_gcm_encrypt(
    uint8_t *ciphertext,
    const uint8_t key[32],
    const uint8_t nonce[12],
    const uint8_t *ad, size_t ad_len,
    const uint8_t *plaintext, size_t text_len);

/**
 * @brief Decrypt with AES-256-GCM.
 * 
 * @param plaintext Pointer to the buffer where the decrypted data will be stored.
 * @param key Pointer to the 32-byte decryption key.
 * @param nonce Pointer to the 12-byte nonce.
 * @param ad Pointer to the additional authenticated data (AAD).
 * @param ad_len Length of the additional authenticated data.
 * @param ciphertext Pointer to the ciphertext data to be decrypted.
 * @param text_len Length of the ciphertext data, excluding the tag.
 * 
 * @return 0 on success, -1 on invalid arguments or authentication failure.
 * 
 * @note This function is intended for use in C environments. For C++ code, use fossil::cryptic::Aes::decrypt instead.
 */
int fossil_cryptic_aes_gcm_decrypt(
    uint8_t *plaintext,
    const uint8_t key[32],
    const uint8_t nonce[12],
    const uint8_t *ad, size_t ad_len,
    const uint8_t *ciphertext, size_t text_len);

#ifdef __cplusplus
}
namespace fossil::cryptic {

    class Aes {
    public:
        /**
         * @brief Encrypts the given plaintext with the provided key, nonce, and additional authenticated data (AAD) using AES-256-GCM.
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
        static int encrypt(uint8_t *ciphertext,
                        const uint8_t key[32],
                        const uint8_t nonce[12],
                        const uint8_t *ad, size_t ad_len,
                        const uint8_t *plaintext, size_t text_len)
        {
            return fossil_cryptic_aes_gcm_encrypt(ciphertext, key, nonce, ad, ad_len, plaintext, text_len);
        }

        /**
         * @brief Decrypts the given ciphertext with the provided key, nonce, and additional authenticated data (AAD) using AES-256-GCM.
         *
         * @param plaintext Pointer to the buffer where the decrypted data will be stored.
         * @param key Pointer to the 32-byte decryption key.
         * @param nonce Pointer to the 12-byte nonce.
         * @param ad Pointer to the additional authenticated data (AAD).
         * @param ad_len Length of the additional authenticated data.
         * @param ciphertext Pointer to the ciphertext data to be decrypted.
         * @param text_len Length of the ciphertext data, excluding the tag.
         *
         * @return 0 on success, -1 on invalid arguments or authentication failure.
         */
        static int decrypt(uint8_t *plaintext,
                        const uint8_t key[32],
                        const uint8_t nonce[12],
                        const uint8_t *ad, size_t ad_len,
                        const uint8_t *ciphertext, size_t text_len)
        {
            return fossil_cryptic_aes_gcm_decrypt(plaintext, key, nonce, ad, ad_len, ciphertext, text_len);
        }
    };

} // namespace cryptic::fossil

#endif

#endif /* FOSSIL_CRYPTIC_AES_H */
