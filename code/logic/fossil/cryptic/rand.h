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
#ifndef FOSSIL_CRYPTIC_RAND_H
#define FOSSIL_CRYPTIC_RAND_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Generates a random value using the specified algorithm, bit width, and output base.
 *
 * This function produces a random value using one of several supported algorithms. The result
 * is formatted according to the specified bit width and output base, and is written as a string
 * to the provided output buffer.
 *
 * @param algorithm
 *      The random number generation algorithm to use. Supported values include:
 *      - "lcg", "xor", "mix", "auto"
 * @param bits
 *      The bit width of the output random value. Supported values:
 *      - "u32", "u64", "auto"
 * @param base
 *      The output encoding/base for the random string. Supported values:
 *      - "hex", "base64", "auto"
 * @param seed
 *      Optional seed value for the random generator (NULL for default/random seed).
 * @param output
 *      Pointer to the buffer where the resulting random string will be written.
 * @param output_len
 *      Size of the output buffer in bytes, including the null terminator.
 * @return
 *      Returns 0 on success. Returns a non-zero value on error (e.g., invalid parameters,
 *      unsupported algorithm, insufficient output buffer size).
 */
int fossil_cryptic_rand_compute(
    const char* algorithm,   // "lcg", "xor", "mix", "auto"
    const char* bits,        // "u32", "u64", "auto"
    const char* base,        // "hex", "base64", "auto"
    const char* seed,        // optional seed (NULL for randomish)
    char* output, size_t output_len
);

#ifdef __cplusplus
}
#include <string>
#include <vector>
#include <array>
#include <stdexcept>

namespace fossil {

    namespace cryptic {

        class Rand {
        public:
            /**
             * @brief Generates a random value using the specified algorithm, bit width, base, and optional seed.
             *
             * @param algorithm
             *      The random number generation algorithm to use. Supported values include:
             *      - "lcg", "xor", "mix", "auto"
             * @param bits
             *      The bit width of the output random value. Supported values:
             *      - "u32", "u64", "auto"
             * @param base
             *      The output encoding/base for the random string. Supported values:
             *      - "hex", "base64", "auto"
             * @param seed
             *      Optional seed value for the random generator (empty string for default/random seed).
             * @return
             *      The resulting random string.
             * @throws std::invalid_argument on invalid parameters.
             * @throws std::runtime_error on random generation errors.
             */
            static std::string compute(
            const std::string& algorithm,
            const std::string& bits,
            const std::string& base,
            const std::string& seed = ""
            ) {
            std::array<char, 128> buffer{};
            const char* seed_ptr = seed.empty() ? nullptr : seed.c_str();
            int result = fossil_cryptic_rand_compute(
                algorithm.c_str(),
                bits.c_str(),
                base.c_str(),
                seed_ptr,
                buffer.data(),
                buffer.size()
            );
            if (result != 0) {
                throw std::runtime_error("Random value generation failed");
            }
            return std::string(buffer.data());
            }
        };

    } // namespace cryptic

} // namespace fossil

#endif

#endif /* FOSSIL_CRYPTIC_HASH_H */
