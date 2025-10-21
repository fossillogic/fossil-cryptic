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
#ifndef FOSSIL_CRYPTIC_SIGN_H
#define FOSSIL_CRYPTIC_SIGN_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Signs input data, optionally with a timestamp.
 *
 * Signs input: returns 0 on success.
 * - algorithm, bits, base: forwarded to fossil_cryptic_auth_compute
 * - key: secret key string
 * - timestamp:
 *      NULL or "auto" -> signer will prefix current unix time + ":" to data before signing
 *      "" or "none"    -> no timestamp is used (signature only)
 *      otherwise       -> the provided timestamp string is prefixed to data before signing
 * - output: receives either "<timestamp>:<signature>" or "<signature>" depending on timestamp usage
 */
int fossil_cryptic_sign(
    const char* algorithm,
    const char* bits,
    const char* base,
    const char* key,
    const void* input, size_t input_len,
    const char* timestamp,
    char* output, size_t output_len
);

/**
 * @brief Verifies a signature.
 *
 * Verifies signature. Returns:
 *   0 -> signature valid
 *   1 -> signature invalid (mismatch)
 *  <0 -> error (e.g. bad args)
 *   if ok_out != NULL it will be set to 1 (valid) or 0 (invalid).
 */
int fossil_cryptic_check(
    const char* algorithm,
    const char* bits,
    const char* base,
    const char* key,
    const void* input, size_t input_len,
    const char* signature, /* "<timestamp>:<sig>" or "<sig>" */
    int* ok_out
);

#ifdef __cplusplus
}
#include <stdexcept>
#include <string>
#include <vector>
#include <array>

namespace fossil {

    namespace cryptic {

        class Sign {
        public:
            /**
             * @brief Signs input data, optionally with a timestamp.
             *
             * @param algorithm  Hash algorithm to use (e.g., "sha256").
             * @param bits       Bit size or mode (e.g., "u32", "u64", or "auto").
             * @param base       Output encoding (e.g., "hex", "base64", or "auto").
             * @param key        Secret key for signing.
             * @param input      Pointer to input data.
             * @param input_len  Length of input data in bytes.
             * @param timestamp  Timestamp string, "auto", "none", or NULL.
             * @param output     Buffer to receive the output signature.
             * @param output_len Size of the output buffer in bytes.
             * @return           0 on success, non-zero on failure.
             */
            static int sign(
            const std::string& algorithm,
            const std::string& bits,
            const std::string& base,
            const std::string& key,
            const void* input, size_t input_len,
            const std::string& timestamp,
            char* output, size_t output_len)
            {
            return fossil_cryptic_sign(
                algorithm.c_str(),
                bits.c_str(),
                base.c_str(),
                key.c_str(),
                input, input_len,
                timestamp.empty() ? nullptr : timestamp.c_str(),
                output, output_len);
            }
        };

        class Check {
        public:
            /**
             * @brief Verifies a signature.
             *
             * @param algorithm  Hash algorithm to use (e.g., "sha256").
             * @param bits       Bit size or mode (e.g., "u32", "u64", or "auto").
             * @param base       Output encoding (e.g., "hex", "base64", or "auto").
             * @param key        Secret key for verification.
             * @param input      Pointer to input data.
             * @param input_len  Length of input data in bytes.
             * @param signature  Signature string ("<timestamp>:<sig>" or "<sig>").
             * @param ok_out     Pointer to int to receive result (1=valid, 0=invalid).
             * @return           0 if valid, 1 if invalid, <0 on error.
             */
            static int verify(
            const std::string& algorithm,
            const std::string& bits,
            const std::string& base,
            const std::string& key,
            const void* input, size_t input_len,
            const std::string& signature,
            int* ok_out)
            {
            return fossil_cryptic_check(
                algorithm.c_str(),
                bits.c_str(),
                base.c_str(),
                key.c_str(),
                input, input_len,
                signature.c_str(),
                ok_out);
            }
        };

    } // namespace cryptic

} // namespace fossil

#endif

#endif /* FOSSIL_CRYPTIC_HASH_H */
