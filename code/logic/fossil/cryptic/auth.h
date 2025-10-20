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
#ifndef FOSSIL_CRYPTIC_AUTH_H
#define FOSSIL_CRYPTIC_AUTH_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file auth.h
 * @brief Header file for authentication logic in the Fossil Cryptic project.
 *
 * This file is intended to declare the interfaces, structures, and constants
 * related to authentication mechanisms used within the Fossil Cryptic codebase.
 * It should be included by source files that require access to authentication
 * functionality, such as user verification, credential management, or session
 * handling.
 *
 * Typical contents of this header may include:
 *   - Function prototypes for authentication routines.
 *   - Data structures representing authentication contexts or user credentials.
 *   - Macros and constants relevant to authentication logic.
 *
 * @note
 * Ensure that any sensitive information or implementation details are not exposed
 * in this header. Only declare what is necessary for other modules to interact
 * with the authentication subsystem.
 *
 * @author dreamer-coding
 * @date   (Add date here)
 */
int fossil_cryptic_auth_compute(
    const char* algorithm,   // hash algorithm
    const char* bits,        // u32, u64, or auto
    const char* base,        // hex, base64, auto
    const char* key,         // secret key
    const void* input, size_t input_len,
    char* output, size_t output_len
);

#ifdef __cplusplus
}
#include <stdexcept>
#include <string>
#include <vector>
#include <array>

namespace fossil {

    namespace cryptic {

        /**
         * @class Auth
         * @brief C++ wrapper for authentication logic in the Fossil Cryptic project.
         *
         * The Auth class provides a static interface for computing authentication
         * hashes using various algorithms, bit sizes, and output encodings. It acts
         * as a C++-friendly wrapper around the underlying C function
         * fossil_cryptic_auth_compute, enabling seamless integration with C++ codebases.
         *
         * Usage example:
         * @code
         *     std::string algorithm = "sha256";
         *     std::string bits = "u32";
         *     std::string base = "hex";
         *     std::string key = "my_secret_key";
         *     const void* input = ...;
         *     size_t input_len = ...;
         *     char output[128];
         *     int result = fossil::cryptic::Auth::compute(
         *         algorithm, bits, base, key, input, input_len, output, sizeof(output)
         *     );
         * @endcode
         *
         * @note
         * This class is intended for use in C++ environments only. For C code,
         * use the fossil_cryptic_auth_compute function directly.
         */
        class Auth {
        public:
            /**
             * @brief Compute an authentication hash.
             *
             * This static method computes an authentication hash using the specified
             * algorithm, bit size, base encoding, and secret key. The result is written
             * to the provided output buffer.
             *
             * @param algorithm  Hash algorithm to use (e.g., "sha256").
             * @param bits       Bit size or mode (e.g., "u32", "u64", or "auto").
             * @param base       Output encoding (e.g., "hex", "base64", or "auto").
             * @param key        Secret key for authentication.
             * @param input      Pointer to input data.
             * @param input_len  Length of input data in bytes.
             * @param output     Buffer to receive the output hash.
             * @param output_len Size of the output buffer in bytes.
             * @return           0 on success, non-zero on failure.
             */
            static int compute(
            const std::string& algorithm,
            const std::string& bits,
            const std::string& base,
            const std::string& key,
            const void* input, size_t input_len,
            char* output, size_t output_len)
            {
                return fossil_cryptic_auth_compute(
                    algorithm.c_str(),
                    bits.c_str(),
                    base.c_str(),
                    key.c_str(),
                    input, input_len,
                    output, output_len);
            }
        };

    } // namespace cryptic

} // namespace fossil

#endif

#endif /* FOSSIL_CRYPTIC_HASH_H */
