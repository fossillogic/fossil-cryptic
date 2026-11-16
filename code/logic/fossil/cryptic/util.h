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
#ifndef FOSSIL_CRYPTIC_UTIL_H
#define FOSSIL_CRYPTIC_UTIL_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Securely wipe memory (volatile, cannot be optimized away).
 * 
 * @param buf Pointer to the memory buffer to be wiped.
 * @param len Length of the memory buffer in bytes.
 * 
 * @note This function is intended for use in C environments. For C++ code, use fossil::cryptic::Util::wipe instead.
*/
void fossil_cryptic_util_wipe(void *buf, size_t len);

/**
 * Constant-time memory comparison.
 * 
 * @param a Pointer to the first memory buffer.
 * @param b Pointer to the second memory buffer.
 * @param len Length of the memory buffers in bytes.
 * 
 * @return 0 if equal, non-zero otherwise.
 * 
 * @note This function is intended for use in C environments. For C++ code, use fossil::cryptic::Util::ct_memcmp instead.
 */
int fossil_cryptic_util_ct_memcmp(const void *a, const void *b, size_t len);

/**
 * Constant-time 16-byte tag comparison.
 * 
 * @param a Pointer to the first 16-byte tag.
 * @param b Pointer to the second 16-byte tag.
 * 
 * @return 0 if equal, -1 otherwise.
 * 
 * @note This function is intended for use in C environments. For C++ code, use fossil::cryptic::Util::verify16 instead.
 */
int fossil_cryptic_util_verify16(const uint8_t a[16], const uint8_t b[16]);

#ifdef __cplusplus
}
#include <stdexcept>

namespace fossil::cryptic {

    class Util {
    public:
        /**
         * @brief Securely wipes memory, ensuring that the operation is not optimized away by the compiler.
         * 
         * @param buf Pointer to the memory buffer to be wiped.
         * @param len Length of the memory buffer in bytes.
         * @note This function is intended for use in C++ environments only. For C code, use fossil_cryptic_util_wipe directly.
         */
        static void wipe(void *buf, size_t len) {
            fossil_cryptic_util_wipe(buf, len);
        }

        /**
         * @brief Performs a constant-time memory comparison between two buffers.
         * 
         * @param a Pointer to the first memory buffer.
         * @param b Pointer to the second memory buffer.
         * @param len Length of the memory buffers in bytes.
         * @return 0 if equal, non-zero otherwise.
         * @note This function is intended for use in C++ environments only. For C code, use fossil_cryptic_util_ct_memcmp directly.
         */
        static int ct_memcmp(const void *a, const void *b, size_t len) {
            return fossil_cryptic_util_ct_memcmp(a, b, len);
        }

        /**
         * @brief Performs a constant-time comparison of two 16-byte tags.
         * 
         * @param a Pointer to the first 16-byte tag.
         * @param b Pointer to the second 16-byte tag.
         * @return 0 if equal, -1 otherwise.
         * @note This function is intended for use in C++ environments only. For C code, use fossil_cryptic_util_verify16 directly.
         */
        static int verify16(const uint8_t a[16], const uint8_t b[16]) {
            return fossil_cryptic_util_verify16(a, b);
        }
    };

} // namespace fossil::cryptic

#endif

#endif /* FOSSIL_CRYPTIC_UTIL_H */
