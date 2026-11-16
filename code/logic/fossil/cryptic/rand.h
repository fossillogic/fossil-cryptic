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
#ifndef FOSSIL_CRYPTIC_RAND_H
#define FOSSIL_CRYPTIC_RAND_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Fill a buffer with cryptographically secure random bytes.
 * Uses the best available OS CSPRNG.
 *
 * @param out  Output buffer
 * @param len  Number of bytes to generate
 * 
 * @return     0 on success, negative on failure
 * 
 * @note This function is intended for use in C environments. For C++ code, use fossil::cryptic::Rand::bytes instead.
 */
int fossil_cryptic_rand_bytes(uint8_t *out, size_t len);

#ifdef __cplusplus
}
#include <vector>
#include <stdexcept>

namespace fossil::cryptic {

    class Rand {
    public:
        /**
         * Fill a buffer with cryptographically secure random bytes.
         * Uses the best available OS CSPRNG.
         *
         * @param out  Output buffer
         * @param len  Number of bytes to generate
         * 
         * @throws std::runtime_error if the underlying C function fails
         */
        static void bytes(uint8_t *out, size_t len) {
            if (fossil_cryptic_rand_bytes(out, len) != 0) {
                throw std::runtime_error("fossil_cryptic_rand_bytes failed");
            }
        }

        /**
         * Generate a vector of cryptographically secure random bytes.
         * Uses the best available OS CSPRNG.
         *
         * @param len  Number of bytes to generate
         * 
         * @return     A vector containing the generated random bytes
         * 
         * @throws std::runtime_error if the underlying C function fails
         */
        static std::vector<uint8_t> bytes(size_t len) {
            std::vector<uint8_t> v(len);
            bytes(v.data(), len);
            return v;
        }
    };

} // namespace fossil::cryptic

#endif

#endif /* FOSSIL_CRYPTIC_RAND_H */
