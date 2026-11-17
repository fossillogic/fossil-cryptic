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
#ifndef FOSSIL_CRYPTIC_KEYGEN_H
#define FOSSIL_CRYPTIC_KEYGEN_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief HKDF using HMAC-SHA256.
 * 
 * @param ikm Pointer to the input keying material.
 * @param ikm_len Length of the input keying material in bytes.
 * @param salt Pointer to the optional salt value (can be NULL).
 * @param salt_len Length of the salt value in bytes (0 if salt is NULL).
 * @param info Pointer to the optional context and application specific information (can be NULL).
 * @param info_len Length of the info value in bytes (0 if info is NULL).
 * @param okm Pointer to the output keying material buffer.
 * @param okm_len Length of the output keying material in bytes.
 * 
 * @return 0 on success, non-zero on failure.
 * 
 * @note This function is intended for use in C environments. For C++ code, use fossil::cryptic::Keygen::hkdf_sha256 instead.
 */
int fossil_cryptic_keygen_hkdf_sha256(
    const uint8_t *ikm, size_t ikm_len,
    const uint8_t *salt, size_t salt_len,
    const uint8_t *info, size_t info_len,
    uint8_t *okm, size_t okm_len);

/**
 * @brief PBKDF2 using HMAC-SHA256.
 * 
 * @param password Pointer to the password.
 * @param password_len Length of the password in bytes.
 * @param salt Pointer to the salt value.
 * @param salt_len Length of the salt value in bytes.
 * @param iterations Number of iterations to perform.
 * @param out Pointer to the output derived key buffer.
 * @param out_len Length of the output derived key in bytes.
 * 
 * @return 0 on success, non-zero on failure.
 * 
 * @note This function is intended for use in C environments. For C++ code, use fossil::cryptic::Keygen::pbkdf2_sha256 instead.
 */
int fossil_cryptic_keygen_pbkdf2_sha256(
    const uint8_t *password, size_t password_len,
    const uint8_t *salt, size_t salt_len,
    uint32_t iterations,
    uint8_t *out, size_t out_len);

#ifdef __cplusplus
}
#include <vector>
#include <stdexcept>

namespace fossil::cryptic {

    class Keygen {
    public:
        /**
         * @brief HKDF using HMAC-SHA256.
         *
         * @param ikm Pointer to the input keying material.
         * @param ikm_len Length of the input keying material in bytes.
         * @param salt Pointer to the optional salt value (can be NULL).
         * @param salt_len Length of the salt value in bytes (0 if salt is NULL).
         * @param info Pointer to the optional context and application specific information (can be NULL).
         * @param info_len Length of the info value in bytes (0 if info is NULL).
         * @param okm_len Length of the output keying material in bytes.
         *
         * @return A vector containing the output keying material.
         *
         * @throws std::runtime_error if the underlying C function fails.
         */
        static std::vector<uint8_t> hkdf_sha256(
            const uint8_t *ikm, size_t ikm_len,
            const uint8_t *salt, size_t salt_len,
            const uint8_t *info, size_t info_len,
            size_t okm_len)
        {
            std::vector<uint8_t> okm(okm_len);
            if (fossil_cryptic_keygen_hkdf_sha256(ikm, ikm_len, salt, salt_len,
                                                info, info_len, okm.data(), okm_len) != 0)
                throw std::runtime_error("hkdf_sha256 failed");
            return okm;
        }

        /**
         * @brief PBKDF2 using HMAC-SHA256.
         *
         * @param password Pointer to the password.
         * @param password_len Length of the password in bytes.
         * @param salt Pointer to the salt value.
         * @param salt_len Length of the salt value in bytes.
         * @param iterations Number of iterations to perform.
         * @param out_len Length of the output derived key in bytes.
         *
         * @return A vector containing the derived key.
         *
         * @throws std::runtime_error if the underlying C function fails.
         */
        static std::vector<uint8_t> pbkdf2_sha256(
            const uint8_t *password, size_t password_len,
            const uint8_t *salt, size_t salt_len,
            uint32_t iterations, size_t out_len)
        {
            std::vector<uint8_t> out(out_len);
            if (fossil_cryptic_keygen_pbkdf2_sha256(password, password_len, salt, salt_len,
                                                    iterations, out.data(), out_len) != 0)
                throw std::runtime_error("pbkdf2_sha256 failed");
            return out;
        }
    };

} // namespace cryptic::fossil

#endif

#endif /* FOSSIL_CRYPTIC_KEYGEN_H */
