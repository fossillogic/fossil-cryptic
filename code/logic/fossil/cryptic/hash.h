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
#ifndef FOSSIL_CRYPTIC_HASH_H
#define FOSSIL_CRYPTIC_HASH_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C"
{
#endif

/* ========== Cryptographic hashes (binary output) ========== */

/**
 * @brief Computes the BLAKE2b-512 hash of the input data.
 *
 * @param in Pointer to the input data.
 * @param in_len Length of the input data in bytes.
 * @param out Pointer to a buffer where the 64-byte hash will be stored.
 *
 * @return 0 on success, non-zero on failure.
 *
 * @note This function is intended for use in C environments. For C++ code, use fossil::cryptic::Hash::blake2b_512 instead.
 */
int fossil_cryptic_hash_blake2b_512(const void *in, size_t in_len, uint8_t out[64]);

/**
 * @brief Computes the BLAKE2b-256 hash of the input data.
 *
 * @param in Pointer to the input data.
 * @param in_len Length of the input data in bytes.
 * @param out Pointer to a buffer where the 32-byte hash will be stored.
 *
 * @return 0 on success, non-zero on failure.
 *
 * @note This function is intended for use in C environments. For C++ code, use fossil::cryptic::Hash::blake2b_256 instead.
 */
int fossil_cryptic_hash_blake2b_256(const void *in, size_t in_len, uint8_t out[32]);

/**
 * @brief Computes the SHA-256 hash of the input data.
 *
 * @param in Pointer to the input data.
 * @param in_len Length of the input data in bytes.
 * @param out Pointer to a buffer where the 32-byte hash will be stored.
 *
 * @return 0 on success, non-zero on failure.
 *
 * @note This function is intended for use in C environments. For C++ code, use fossil::cryptic::Hash::sha256 instead.
 */
int fossil_cryptic_hash_sha256(const void *in, size_t in_len, uint8_t out[32]);

/**
 * @brief Computes the SHA-512 hash of the input data.
 *
 * @param in Pointer to the input data.
 * @param in_len Length of the input data in bytes.
 * @param out Pointer to a buffer where the 64-byte hash will be stored.
 *
 * @return 0 on success, non-zero on failure.
 *
 * @note This function is intended for use in C environments. For C++ code, use fossil::cryptic::Hash::sha512 instead.
 */
int fossil_cryptic_hash_sha512(const void *in, size_t in_len, uint8_t out[64]);

/* ========== Non-cryptographic (utility only) ========== */

/**
 * @brief Computes the CRC32 checksum of the input data.
 *
 * @param in Pointer to the input data.
 * @param in_len Length of the input data in bytes.
 *
 * @return The computed CRC32 checksum.
 *
 * @note This function is intended for use in C environments. For C++ code, use fossil::cryptic::Hash::crc32 instead.
 */
uint32_t fossil_cryptic_hash_crc32(const void *in, size_t in_len);

/**
 * @brief Computes the CRC64 checksum of the input data.
 *
 * @param in Pointer to the input data.
 * @param in_len Length of the input data in bytes.
 *
 * @return The computed CRC64 checksum.
 *
 * @note This function is intended for use in C environments. For C++ code, use fossil::cryptic::Hash::crc64 instead.
 */
uint64_t fossil_cryptic_hash_crc64(const void *in, size_t in_len);

/**
 * @brief Computes the FNV-32 hash of the input data.
 *
 * @param in Pointer to the input data.
 * @param in_len Length of the input data in bytes.
 *
 * @return The computed FNV-32 hash.
 *
 * @note This function is intended for use in C environments. For C++ code, use fossil::cryptic::Hash::fnv32 instead.
 */
uint32_t fossil_cryptic_hash_fnv32(const void *in, size_t in_len);

/**
 * @brief Computes the FNV-64 hash of the input data.
 *
 * @param in Pointer to the input data.
 * @param in_len Length of the input data in bytes.
 *
 * @return The computed FNV-64 hash.
 *
 * @note This function is intended for use in C environments. For C++ code, use fossil::cryptic::Hash::fnv64 instead.
 */
uint64_t fossil_cryptic_hash_fnv64(const void *in, size_t in_len);

/**
 * @brief Computes the DJB2 hash of the input data.
 *
 * @param in Pointer to the input data.
 * @param in_len Length of the input data in bytes.
 *
 * @return The computed DJB2 hash.
 *
 * @note This function is intended for use in C environments. For C++ code, use fossil::cryptic::Hash::djb2 instead.
 */
uint32_t fossil_cryptic_hash_djb2(const void *in, size_t in_len);

/**
 * @brief Computes the SDBM hash of the input data.
 *
 * @param in Pointer to the input data.
 * @param in_len Length of the input data in bytes.
 *
 * @return The computed SDBM hash.
 *
 * @note This function is intended for use in C environments. For C++ code, use fossil::cryptic::Hash::sdbm instead.
 */
uint32_t fossil_cryptic_hash_sdbm(const void *in, size_t in_len);

#ifdef __cplusplus
}
#include <array>
#include <vector>
#include <stdexcept>

namespace fossil::cryptic
{

    class Hash
    {
    public:
        /**
         * @brief Computes the BLAKE2b-512 hash of the input data.
         *
         * @param in Pointer to the input data.
         * @param len Length of the input data in bytes.
         * @return A std::array containing the 64-byte hash.
         * @throws std::runtime_error if the underlying C function fails.
         */
        static std::array<uint8_t, 64> blake2b_512(const void *in, size_t len)
        {
            std::array<uint8_t, 64> out{};
            if (fossil_cryptic_hash_blake2b_512(in, len, out.data()) != 0)
                throw std::runtime_error("blake2b_512 failed");
            return out;
        }

        /**
         * @brief Computes the BLAKE2b-256 hash of the input data.
         *
         * @param in Pointer to the input data.
         * @param len Length of the input data in bytes.
         * @return A std::array containing the 32-byte hash.
         * @throws std::runtime_error if the underlying C function fails.
         */
        static std::array<uint8_t, 32> sha256(const void *in, size_t len)
        {
            std::array<uint8_t, 32> out{};
            if (fossil_cryptic_hash_sha256(in, len, out.data()) != 0)
                throw std::runtime_error("sha256 failed");
            return out;
        }

        /**
         * @brief Computes the SHA-512 hash of the input data.
         *
         * @param in Pointer to the input data.
         * @param len Length of the input data in bytes.
         * @return A std::array containing the 64-byte hash.
         * @throws std::runtime_error if the underlying C function fails.
         */
        static std::array<uint8_t, 32> blake2b_256(const void *in, size_t len)
        {
            std::array<uint8_t, 32> out{};
            if (fossil_cryptic_hash_blake2b_256(in, len, out.data()) != 0)
                throw std::runtime_error("blake2b_256 failed");
            return out;
        }

        /**
         * @brief Computes the SHA-512 hash of the input data.
         *
         * @param in Pointer to the input data.
         * @param len Length of the input data in bytes.
         * @return A std::array containing the 64-byte hash.
         * @throws std::runtime_error if the underlying C function fails.
         */
        static std::array<uint8_t, 64> sha512(const void *in, size_t len)
        {
            std::array<uint8_t, 64> out{};
            if (fossil_cryptic_hash_sha512(in, len, out.data()) != 0)
                throw std::runtime_error("sha512 failed");
            return out;
        }

        /**
         * @brief Computes the CRC32 checksum of the input data.
         *
         * @param in Pointer to the input data.
         * @param len Length of the input data in bytes.
         * @return The computed CRC32 checksum.
         */
        static uint32_t crc32(const void *in, size_t len)
        {
            return fossil_cryptic_hash_crc32(in, len);
        }

        /**
         * @brief Computes the CRC64 checksum of the input data.
         *
         * @param in Pointer to the input data.
         * @param len Length of the input data in bytes.
         * @return The computed CRC64 checksum.
         */
        static uint64_t crc64(const void *in, size_t len)
        {
            return fossil_cryptic_hash_crc64(in, len);
        }

        /**
         * @brief Computes the FNV-32 hash of the input data.
         *
         * @param in Pointer to the input data.
         * @param len Length of the input data in bytes.
         * @return The computed FNV-32 hash.
         */
        static uint32_t fnv32(const void *in, size_t len)
        {
            return fossil_cryptic_hash_fnv32(in, len);
        }

        /**
         * @brief Computes the FNV-64 hash of the input data.
         *
         * @param in Pointer to the input data.
         * @param len Length of the input data in bytes.
         * @return The computed FNV-64 hash.
         */
        static uint64_t fnv64(const void *in, size_t len)
        {
            return fossil_cryptic_hash_fnv64(in, len);
        }

        /**
         * @brief Computes the DJB2 hash of the input data.
         *
         * @param in Pointer to the input data.
         * @param len Length of the input data in bytes.
         * @return The computed DJB2 hash.
         */
        static uint32_t djb2(const void *in, size_t len)
        {
            return fossil_cryptic_hash_djb2(in, len);
        }

        /**
         * @brief Computes the SDBM hash of the input data.
         *
         * @param in Pointer to the input data.
         * @param len Length of the input data in bytes.
         * @return The computed SDBM hash.
         */
        static uint32_t sdbm(const void *in, size_t len)
        {
            return fossil_cryptic_hash_sdbm(in, len);
        }
    };

} // namespace cryptic::fossil

#endif

#endif /* FOSSIL_CRYPTIC_HASH_H */
