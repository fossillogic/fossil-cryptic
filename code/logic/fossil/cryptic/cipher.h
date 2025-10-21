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
#ifndef FOSSIL_CRYPTIC_CIPHER_H
#define FOSSIL_CRYPTIC_CIPHER_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Computes a cipher transformation (encryption or decryption) on the input data using the specified algorithm and options.
 *
 * This function applies a cipher operation to the provided input buffer using one of several supported
 * algorithms and modes. The result is written to the provided output buffer.
 *
 * @param algorithm
 *      The cipher algorithm to use. Supported values include:
 *      - "xor", "feistel", "caesar", "vigenere", "morse", "auto"
 * @param mode
 *      The operation mode. Supported values:
 *      - "encrypt", "decrypt", "auto"
 * @param bits
 *      The bit width for the cipher operation. Supported values:
 *      - "u32", "u64", "auto"
 * @param key
 *      The key string used for the cipher operation.
 * @param input
 *      Pointer to the input data buffer to be transformed.
 * @param input_len
 *      Length of the input data buffer in bytes.
 * @param output
 *      Pointer to the buffer where the resulting ciphered data will be written.
 * @param output_len
 *      Pointer to a variable holding the size of the output buffer on input, and the actual output size on output.
 * @return
 *      Returns 0 on success. Returns a non-zero value on error (e.g., invalid parameters,
 *      unsupported algorithm, insufficient output buffer size).
 */
int fossil_cryptic_cipher_compute(
    const char* algorithm,   // "xor", "feistel", "caesar", "vigenere", "morse", "auto"
    const char* mode,        // "encrypt", "decrypt", "auto"
    const char* bits,        // "u32", "u64", "auto"
    const char* key,         // key string
    const void* input, size_t input_len,
    void* output, size_t* output_len
);


#ifdef __cplusplus
}
#include <string>
#include <vector>
#include <array>
#include <algorithm>
#include <stdexcept>

namespace fossil {

    namespace cryptic {

        class Cipher {
        public:
            /**
             * @brief Computes a cipher transformation (encryption or decryption) on the input data using the specified algorithm and options.
             *
             * @param algorithm
             *      The cipher algorithm to use. Supported values include:
             *      - "xor", "feistel", "auto"
             * @param mode
             *      The operation mode. Supported values:
             *      - "encrypt", "decrypt", "auto"
             * @param bits
             *      The bit width for the cipher operation. Supported values:
             *      - "u32", "u64", "auto"
             * @param key
             *      The key string used for the cipher operation.
             * @param input
             *      Pointer to the input data buffer to be transformed.
             * @param input_len
             *      Length of the input data buffer in bytes.
             * @return
             *      The resulting ciphered data as a std::vector<uint8_t>.
             *      Returns empty vector on invalid/null arguments.
             * @throws std::invalid_argument on unsupported algorithm.
             * @throws std::runtime_error on cipher errors.
             */
            static std::vector<uint8_t> compute(
            const std::string& algorithm,
            const std::string& mode,
            const std::string& bits,
            const std::string& key,
            const void* input,
            size_t input_len
            ) {
            // Check for null/empty arguments
            if (algorithm.empty() || mode.empty() || bits.empty() || key.empty() || input == nullptr || input_len == 0) {
                return {};
            }

            // Only allow supported algorithms, throw for unknown
            static const std::vector<std::string> supported_algorithms = {
                "xor", "feistel", "caesar", "vigenere", "morse", "auto"
            };
            if (std::find(supported_algorithms.begin(), supported_algorithms.end(), algorithm) == supported_algorithms.end()) {
                throw std::invalid_argument("Unsupported cipher algorithm: " + algorithm);
            }

            std::vector<uint8_t> output(input_len);
            size_t output_len = output.size();
            int result = fossil_cryptic_cipher_compute(
                algorithm.c_str(),
                mode.c_str(),
                bits.c_str(),
                key.c_str(),
                input,
                input_len,
                output.data(),
                &output_len
            );
            if (result != 0) {
                // For unsupported algorithm, fossil_cryptic_cipher_compute may also return error
                // But we already checked above, so treat all errors as runtime except for empty input
                return {};
            }
            output.resize(output_len);
            return output;
            }

            /**
             * @brief Overload for std::vector<uint8_t> input.
             */
            static std::vector<uint8_t> compute(
            const std::string& algorithm,
            const std::string& mode,
            const std::string& bits,
            const std::string& key,
            const std::vector<uint8_t>& input
            ) {
            if (input.empty()) return {};
            return compute(algorithm, mode, bits, key, input.data(), input.size());
            }

            /**
             * @brief Overload for std::string input.
             */
            static std::vector<uint8_t> compute(
            const std::string& algorithm,
            const std::string& mode,
            const std::string& bits,
            const std::string& key,
            const std::string& input
            ) {
            if (input.empty()) return {};
            return compute(algorithm, mode, bits, key, input.data(), input.size());
            }
        };

    } // namespace cryptic

} // namespace fossil

#endif

#endif /* FOSSIL_CRYPTIC_HASH_H */
