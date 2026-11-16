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
#ifndef FOSSIL_CRYPTIC_AUTH_H
#define FOSSIL_CRYPTIC_AUTH_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/** 
 * @brief Compute HMAC using SHA-256.
 *
 * @param key Pointer to the key.
 * @param key_len Length of the key in bytes.
 * @param msg Pointer to the message.
 * @param msg_len Length of the message in bytes.
 * @param out Pointer to a buffer where the 32-byte HMAC will be stored.
 *
 * @return 0 on success, non-zero on failure.
 *
 * @note This function is intended for use in C environments. For C++ code, use fossil::cryptic::Auth::hmac_sha256 instead.
 */
int fossil_cryptic_auth_hmac_sha256(
    const uint8_t *key, size_t key_len,
    const void *msg, size_t msg_len,
    uint8_t out[32]);

/** 
 * @brief Compute HMAC using BLAKE2b-512.
 * 
 * @param key Pointer to the key.
 * @param key_len Length of the key in bytes.
 * @param msg Pointer to the message.
 * @param msg_len Length of the message in bytes.
 * @param out Pointer to a buffer where the 64-byte HMAC will be stored.
 * 
 * @return 0 on success, non-zero on failure.
 * 
 * @note This function is intended for use in C environments. For C++ code, use fossil::cryptic::Auth::hmac_blake2b_512 instead.
 */
int fossil_cryptic_auth_hmac_blake2b_512(
    const uint8_t *key, size_t key_len,
    const void *msg, size_t msg_len,
    uint8_t out[64]);

#ifdef __cplusplus
}
#include <array>
#include <stdexcept>

namespace fossil::cryptic {

    class Auth {
    public:
        /**
         * @brief Computes the HMAC using SHA-256.
         *
         * @param key Pointer to the key.
         * @param key_len Length of the key in bytes.
         * @param msg Pointer to the message.
         * @param msg_len Length of the message in bytes.
         * @return A std::array containing the 32-byte HMAC.
         * @throws std::runtime_error if the underlying C function fails.
         */
        static std::array<uint8_t, 32> hmac_sha256(
            const uint8_t *key, size_t key_len,
            const void *msg, size_t msg_len)
        {
            std::array<uint8_t, 32> out{};
            if (fossil_cryptic_auth_hmac_sha256(key, key_len, msg, msg_len, out.data()) != 0)
                throw std::runtime_error("hmac_sha256 failed");
            return out;
        }

        /**
         * @brief Computes the HMAC using BLAKE2b-512.
         *
         * @param key Pointer to the key.
         * @param key_len Length of the key in bytes.
         * @param msg Pointer to the message.
         * @param msg_len Length of the message in bytes.
         * @return A std::array containing the 64-byte HMAC.
         * @throws std::runtime_error if the underlying C function fails.
         */
        static std::array<uint8_t, 64> hmac_blake2b_512(
            const uint8_t *key, size_t key_len,
            const void *msg, size_t msg_len)
        {
            std::array<uint8_t, 64> out{};
            if (fossil_cryptic_auth_hmac_blake2b_512(key, key_len, msg, msg_len, out.data()) != 0)
                throw std::runtime_error("hmac_blake2b_512 failed");
            return out;
        }
    };

} // namespace cryptic::fossil

#endif

#endif /* FOSSIL_CRYPTIC_AUTH_H */
