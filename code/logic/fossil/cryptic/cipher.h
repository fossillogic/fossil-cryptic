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
#ifndef FOSSIL_CRYPTIC_CIPHER_H
#define FOSSIL_CRYPTIC_CIPHER_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C"
{
#endif

/**
 * @brief XOR cipher (symmetric).
 *
 * @param key Pointer to the key.
 * @param key_len Length of the key in bytes.
 * @param in Pointer to the input data.
 * @param in_len Length of the input data in bytes.
 * @param out Pointer to the output buffer where the result will be stored.
 *
 * @return 0 on success, non-zero on failure.
 *
 * @note This function is intended for use in C environments. For C++ code, use fossil::cryptic::Cipher::xor_cipher instead.
 */
int fossil_cryptic_cipher_xor(
    const uint8_t *key, size_t key_len,
    const uint8_t *in, size_t in_len,
    uint8_t *out);

/**
 * @brief Caesar cipher (symmetric). Only affects A-Z / a-z.
 *
 * @param shift The number of positions to shift each letter (positive for right shift, negative for left shift).
 * @param in Pointer to the input data.
 * @param in_len Length of the input data in bytes.
 * @param out Pointer to the output buffer where the result will be stored.
 *
 * @return 0 on success, non-zero on failure.
 *
 * @note This function is intended for use in C environments. For C++ code, use fossil::cryptic::Cipher::caesar instead.
 */
int fossil_cryptic_cipher_caesar(
    int shift,
    const uint8_t *in, size_t in_len,
    uint8_t *out);

/**
 * @brief Vigenère cipher (symmetric). Only affects A-Z / a-z.
 *
 * @param key Pointer to the key string (null-terminated).
 * @param encrypt 1 to encrypt, 0 to decrypt.
 * @param in Pointer to the input data.
 * @param in_len Length of the input data in bytes.
 * @param out Pointer to the output buffer where the result will be stored.
 *
 * @return 0 on success, non-zero on failure.
 *
 * @note This function is intended for use in C environments. For C++ code, use fossil::cryptic::Cipher::vigenere instead.
 */
int fossil_cryptic_cipher_vigenere(
    const char *key,
    int encrypt, /* 1 = encrypt, 0 = decrypt */
    const uint8_t *in, size_t in_len,
    uint8_t *out);

#ifdef __cplusplus
}

namespace fossil::cryptic
{

    class Cipher
    {
    public:
        /**
         * @brief XOR cipher (symmetric).
         *
         * @param key Pointer to the key.
         * @param key_len Length of the key in bytes.
         * @param in Pointer to the input data.
         * @param in_len Length of the input data in bytes.
         * @param out Pointer to the output buffer where the result will be stored.
         *
         * @return 0 on success, non-zero on failure.
         */
        static int xor_cipher(const uint8_t *key, size_t key_len,
                              const uint8_t *in, size_t in_len, uint8_t *out)
        {
            return fossil_cryptic_cipher_xor(key, key_len, in, in_len, out);
        }

        /**
         * @brief Caesar cipher (symmetric). Only affects A-Z / a-z.
         *
         * @param shift The number of positions to shift each letter (positive for right shift, negative for left shift).
         * @param in Pointer to the input data.
         * @param in_len Length of the input data in bytes.
         * @param out Pointer to the output buffer where the result will be stored.
         *
         * @return 0 on success, non-zero on failure.
         */
        static int caesar(int shift, const uint8_t *in, size_t in_len, uint8_t *out)
        {
            return fossil_cryptic_cipher_caesar(shift, in, in_len, out);
        }

        /**
         * @brief Vigenère cipher (symmetric). Only affects A-Z / a-z.
         *
         * @param key Pointer to the key string (null-terminated).
         * @param encrypt 1 to encrypt, 0 to decrypt.
         * @param in Pointer to the input data.
         * @param in_len Length of the input data in bytes.
         * @param out Pointer to the output buffer where the result will be stored.
         *
         * @return 0 on success, non-zero on failure.
         */
        static int vigenere(const char *key, int encrypt, const uint8_t *in, size_t in_len, uint8_t *out)
        {
            return fossil_cryptic_cipher_vigenere(key, encrypt, in, in_len, out);
        }
    };

} // namespace cryptic::fossil

#endif

#endif /* FOSSIL_CRYPTIC_CIPHER_H */
