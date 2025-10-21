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
#ifndef FOSSIL_CRYPTIC_HASH_H
#define FOSSIL_CRYPTIC_HASH_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Computes a hash of the given input data using the specified algorithm and formatting options.
 *
 * This function calculates a hash value for the provided input buffer using one of several supported
 * algorithms. The result is formatted according to the specified bit width and output base, and is
 * written as a string to the provided output buffer.
 *
 * @param algorithm
 *      The hash algorithm to use. Supported values include:
 *      - "crc32", "crc64", "fnv32", "fnv64", "xor", "djb2", "sdbm",
 *        "murmur3_32", "murmur3_64", "cityhash32", "cityhash64",
 *        "xxhash32", "xxhash64"
 * @param bits
 *      The bit width of the output hash. Supported values:
 *      - "u32", "u64", "auto"
 * @param base
 *      The output encoding/base for the hash string. Supported values:
 *      - "hex", "dec", "oct", "bin", "auto"
 * @param output
 *      Pointer to the buffer where the resulting hash string will be written.
 * @param output_len
 *      Size of the output buffer in bytes, including the null terminator.
 * @param input
 *      Pointer to the input data buffer to be hashed.
 * @param input_len
 *      Length of the input data buffer in bytes.
 * @return
 *      Returns 0 on success. Returns a non-zero value on error (e.g., invalid parameters,
 *      unsupported algorithm, insufficient output buffer size).
 */
int fossil_cryptic_hash_compute(
    const char* algorithm,
    const char* bits,
    const char* base,
    char* output, size_t output_len,
    const void* input, size_t input_len
);

#ifdef __cplusplus
}
#include <string>
#include <vector>
#include <array>
#include <stdexcept>

namespace fossil {

    namespace cryptic {

        class Hash {
        public:
            /**
             * @brief Computes a hash of the given input data using the specified algorithm and formatting options.
             *
             * @param algorithm
             *      The hash algorithm to use. Supported values include:
             *      - "crc32", "fnv32", "fnv64", "xor", "djb2", "sdbm"
             * @param bits
             *      The bit width of the output hash. Supported values: "u32", "u64", "auto"
             * @param base
             *      The output encoding/base for the hash string. Supported values: "hex", "base64", "auto"
             * @param input
             *      Pointer to the input data buffer to be hashed.
             * @param input_len
             *      Length of the input data buffer in bytes.
             * @return
             *      The resulting hash string.
             * @throws std::invalid_argument on invalid parameters.
             * @throws std::runtime_error on hashing errors.
             */
            static std::string compute(
            const std::string& algorithm,
            const std::string& bits,
            const std::string& base,
            const void* input,
            size_t input_len
            ) {
                // Allocate a sufficiently large buffer for the hash output
                std::array<char, 128> buffer{};
                int result = fossil_cryptic_hash_compute(
                    algorithm.c_str(),
                    bits.c_str(),
                    base.c_str(),
                    buffer.data(),
                    buffer.size(),
                    input,
                    input_len
                );
                if (result != 0) {
                    throw std::runtime_error("Hash computation failed");
                }
                return std::string(buffer.data());
            }

            /**
             * @brief Overload for std::vector<uint8_t> input.
             */
            static std::string compute(
            const std::string& algorithm,
            const std::string& bits,
            const std::string& base,
            const std::vector<uint8_t>& input
            ) {
                return compute(algorithm, bits, base, input.data(), input.size());
            }

            /**
             * @brief Overload for std::string input.
             */
            static std::string compute(
            const std::string& algorithm,
            const std::string& bits,
            const std::string& base,
            const std::string& input
            ) {
                return compute(algorithm, bits, base, input.data(), input.size());
            }
        };

    } // namespace cryptic

} // namespace fossil

#endif

#endif /* FOSSIL_CRYPTIC_HASH_H */
