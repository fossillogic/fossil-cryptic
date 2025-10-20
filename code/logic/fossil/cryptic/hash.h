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

/* ------------------------------------------------------------------------
 * Algorithm identifiers (string-based)
 *
 * Available (case-insensitive):
 *   "fnv1a"      - FNV-1a 32-bit
 *   "fnv1a64"    - FNV-1a 64-bit
 *   "crc32"      - CRC32 (IEEE 802.3 polynomial)
 *   "murmur3"    - MurmurHash3 x86 32-bit
 *   "jenkins"    - Jenkins one-at-a-time (32-bit)
 *   "sha1"       - SHA-1 (160-bit)
 *   "sha256"     - SHA-256 (256-bit)
 *   "sha512"     - SHA-512 (512-bit)
 *
 * More algorithms can be added by extending canonical_alg() in the source.
 * ------------------------------------------------------------------------ */

/**
 * @brief Get a list of available algorithms.
 *
 * @return A newline-separated string listing all supported algorithm IDs.
 *         The string is statically allocated (do not free).
 */
const char *fossil_cryptic_hash_list(void);

/* ------------------------------------------------------------------------
 * Core Hash APIs
 * ------------------------------------------------------------------------ */

/**
 * @brief Compute a 32-bit hash value for a data buffer.
 *
 * @param data   Pointer to input data.
 * @param len    Number of bytes in input.
 * @param alg    Algorithm string ID ("fnv1a", "crc32", etc).
 * @return 32-bit hash value.
 */
uint32_t fossil_cryptic_hash_u32(const void *data, size_t len, const char *alg);

/**
 * @brief Compute a 64-bit hash value for a data buffer.
 *
 * @param data   Pointer to input data.
 * @param len    Number of bytes in input.
 * @param alg    Algorithm string ID.
 * @return 64-bit hash value (native or promoted combination if no native 64).
 */
uint64_t fossil_cryptic_hash_u64(const void *data, size_t len, const char *alg);

/* ------------------------------------------------------------------------
 * Encoded Output Interface
 * ------------------------------------------------------------------------ */

/**
 * @brief Compute a hash and encode to string according to preferences.
 *
 * @param data       Input data buffer.
 * @param len        Length of data in bytes.
 * @param alg        Algorithm string ID.
 * @param bit_pref   "u32", "u64", "sha1", "sha256", "sha512", or "auto" (auto picks best).
 * @param base_pref  "hex", "base64", "base62", "base36", or "auto" (auto → "hex").
 * @param out        Output buffer for encoded string.
 * @param outlen     Size of output buffer in bytes.
 *
 * @return 0 on success, nonzero on error (buffer too small, etc.).
 *
 * Example:
 *     char out[128];
 *     fossil_cryptic_hash_to_str("hello", 5, "sha256", "auto", "base62", out, sizeof(out));
 *     printf("Hash: %s\n", out);
 */
int fossil_cryptic_hash_to_str(const void *data, size_t len,
                               const char *alg, const char *bit_pref,
                               const char *base_pref,
                               char *out, size_t outlen);

/**
 * @brief Convenience helper: compute hash and return a static hex string.
 *
 * Not thread-safe (uses a static internal buffer).
 *
 * @param data  Input buffer.
 * @param len   Length of input.
 * @param alg   Algorithm ID.
 * @return Pointer to static hex string.
 */
char *fossil_cryptic_hash_hex_auto(const void *data, size_t len, const char *alg);

/* ------------------------------------------------------------------------
 * Extended Output Encodings
 * ------------------------------------------------------------------------ */

/**
 * @brief Encode a binary buffer to base62.
 *
 * @param in      Input buffer.
 * @param inlen   Input length.
 * @param out     Output buffer.
 * @param outlen  Output buffer size.
 * @return 0 on success, nonzero on error.
 */
int fossil_cryptic_base62_encode(const void *in, size_t inlen, char *out, size_t outlen);

/**
 * @brief Encode a binary buffer to base36.
 *
 * @param in      Input buffer.
 * @param inlen   Input length.
 * @param out     Output buffer.
 * @param outlen  Output buffer size.
 * @return 0 on success, nonzero on error.
 */
int fossil_cryptic_base36_encode(const void *in, size_t inlen, char *out, size_t outlen);

/* ------------------------------------------------------------------------
 * Options-based API
 * ------------------------------------------------------------------------ */

/**
 * @brief Options struct for hashing.
 *
 * All fields are optional; set to NULL/0 for defaults.
 * Keys are string IDs ("alg", "bit", "base", ...).
 */
typedef struct fossil_cryptic_hash_opts {
    const char *alg;      /**< Algorithm string ID ("sha256", etc) */
    const char *bit;      /**< Bit width or hash type ("u32", "sha512", "auto") */
    const char *base;     /**< Output encoding ("hex", "base62", "base36", "base64", "auto") */
    size_t     outlen;    /**< Output buffer size (0 = default) */
    /* Future: add more options as needed */
} fossil_cryptic_hash_opts;

/**
 * @brief Compute a hash and encode to string using options struct.
 *
 * @param data   Input buffer.
 * @param len    Input length.
 * @param opts   Pointer to options struct (may be NULL for defaults).
 * @param out    Output buffer.
 * @param outlen Output buffer size.
 * @return 0 on success, nonzero on error.
 */
int fossil_cryptic_hash_with_opts(const void *data, size_t len,
                                  const fossil_cryptic_hash_opts *opts,
                                  char *out, size_t outlen);

/* ------------------------------------------------------------------------
 * SHA-1 / SHA-256 / SHA-512 APIs (pure C, available internally)
 * ------------------------------------------------------------------------ */

/**
 * @brief Compute SHA-1 hash (20 bytes).
 *
 * @param data   Input buffer.
 * @param len    Input length.
 * @param out    Output buffer (must be at least 20 bytes).
 */
void fossil_cryptic_sha1(const void *data, size_t len, uint8_t out[20]);

/**
 * @brief Compute SHA-256 hash (32 bytes).
 *
 * @param data   Input buffer.
 * @param len    Input length.
 * @param out    Output buffer (must be at least 32 bytes).
 */
void fossil_cryptic_sha256(const void *data, size_t len, uint8_t out[32]);

/**
 * @brief Compute SHA-512 hash (64 bytes).
 *
 * @param data   Input buffer.
 * @param len    Input length.
 * @param out    Output buffer (must be at least 64 bytes).
 */
void fossil_cryptic_sha512(const void *data, size_t len, uint8_t out[64]);

#ifdef __cplusplus
}
#include <string>
#include <vector>
#include <array>
#include <cstdint>
#include <cstring>

namespace fossil {

    namespace cryptic {

        /**
         * @brief C++ wrapper for one-shot and streaming hashing functions.
         *
         * This class provides both static one-shot hashing methods and
         * an object-oriented streaming interface that wraps the C API.
         * It allows users to compute hashes using various algorithms,
         * encode the result in different formats, and access raw hash bytes.
         */
        class Hash {
        public:
            /**
             * @brief Supported algorithms (string-based, matching C API).
             *
             * Enumerates all hash algorithms supported by the underlying
             * C API. These values map directly to the string IDs used
             * in the C interface.
             */
            enum class Algorithm : uint32_t {
                FNV1a32,      /**< FNV-1a 32-bit hash */
                FNV1a64,      /**< FNV-1a 64-bit hash */
                CRC32,        /**< CRC32 (IEEE 802.3 polynomial) */
                Murmur3_32,   /**< MurmurHash3 x86 32-bit */
                Jenkins,      /**< Jenkins one-at-a-time (32-bit) */
                SHA1,         /**< SHA-1 (160-bit) */
                SHA256,       /**< SHA-256 (256-bit) */
                SHA512        /**< SHA-512 (512-bit) */
            };

            /**
             * @brief Default constructor (no algorithm set).
             *
             * Constructs a Hash object with the default algorithm (FNV1a32).
             */
            Hash() = default;

            /**
             * @brief Construct and initialize with a specific algorithm.
             *
             * @param alg Algorithm to use for hashing operations.
             */
            explicit Hash(Algorithm alg) : alg_(alg) {}

            /**
             * @brief Compute a 32-bit hash for a buffer.
             *
             * Computes a 32-bit hash value for the given data buffer using
             * the specified algorithm.
             *
             * @param data Pointer to input data.
             * @param len  Number of bytes in input.
             * @param alg  Algorithm to use.
             * @return 32-bit hash value.
             */
            static uint32_t hash_32(const void* data, size_t len, Algorithm alg) {
                return fossil_cryptic_hash_u32(data, len, to_alg_str(alg));
            }

            /**
             * @brief Compute a 64-bit hash for a buffer.
             *
             * Computes a 64-bit hash value for the given data buffer using
             * the specified algorithm.
             *
             * @param data Pointer to input data.
             * @param len  Number of bytes in input.
             * @param alg  Algorithm to use.
             * @return 64-bit hash value.
             */
            static uint64_t hash_64(const void* data, size_t len, Algorithm alg) {
                return fossil_cryptic_hash_u64(data, len, to_alg_str(alg));
            }

            /**
             * @brief Compute a hash and encode to string.
             *
             * Computes a hash for the given data buffer using the specified
             * algorithm, bit width, and output encoding, and returns the
             * result as a string.
             *
             * @param data      Input data buffer.
             * @param len       Length of data in bytes.
             * @param alg       Algorithm to use.
             * @param bit_pref  Bit width or hash type ("u32", "sha256", etc).
             * @param base_pref Output encoding ("hex", "base62", etc).
             * @return Encoded hash string, or empty string on error.
             */
            static std::string hash_to_string(const void* data, size_t len, Algorithm alg,
                              const char* bit_pref = "auto",
                              const char* base_pref = "auto") {
                char out[256];
                if (fossil_cryptic_hash_to_str(data, len, to_alg_str(alg), bit_pref, base_pref, out, sizeof(out)) == 0)
                    return std::string(out);
                return {};
            }

            /**
             * @brief Get a static hex string for a hash.
             *
             * Computes a hash for the given data buffer using the specified
             * algorithm and returns a static hex-encoded string.
             * Not thread-safe.
             *
             * @param data Input buffer.
             * @param len  Length of input.
             * @param alg  Algorithm to use.
             * @return Hex-encoded hash string, or empty string on error.
             */
            static std::string hash_hex_auto(const void* data, size_t len, Algorithm alg) {
                char* hex = fossil_cryptic_hash_hex_auto(data, len, to_alg_str(alg));
                return hex ? std::string(hex) : std::string();
            }

            /**
             * @brief Get a list of available algorithms.
             *
             * Returns a newline-separated string listing all supported
             * algorithm IDs. The string is statically allocated.
             *
             * @return String listing available algorithms.
             */
            static std::string available_algorithms() {
                const char* list = fossil_cryptic_hash_list();
                return list ? std::string(list) : std::string();
            }

            /**
             * @brief Compute SHA-1 hash (20 bytes).
             *
             * Computes the SHA-1 hash of the input data and returns the
             * result as a std::array of 20 bytes.
             *
             * @param data Input buffer.
             * @param len  Length of input.
             * @return SHA-1 hash as a 20-byte array.
             */
            static std::array<uint8_t, 20> sha1(const void* data, size_t len) {
                std::array<uint8_t, 20> out{};
                fossil_cryptic_sha1(data, len, out.data());
                return out;
            }

            /**
             * @brief Compute SHA-256 hash (32 bytes).
             *
             * Computes the SHA-256 hash of the input data and returns the
             * result as a std::array of 32 bytes.
             *
             * @param data Input buffer.
             * @param len  Length of input.
             * @return SHA-256 hash as a 32-byte array.
             */
            static std::array<uint8_t, 32> sha256(const void* data, size_t len) {
                std::array<uint8_t, 32> out{};
                fossil_cryptic_sha256(data, len, out.data());
                return out;
            }

            /**
             * @brief Compute SHA-512 hash (64 bytes).
             *
             * Computes the SHA-512 hash of the input data and returns the
             * result as a std::array of 64 bytes.
             *
             * @param data Input buffer.
             * @param len  Length of input.
             * @return SHA-512 hash as a 64-byte array.
             */
            static std::array<uint8_t, 64> sha512(const void* data, size_t len) {
                std::array<uint8_t, 64> out{};
                fossil_cryptic_sha512(data, len, out.data());
                return out;
            }

        private:
            /**
             * @brief Algorithm to use for hashing operations.
             *
             * Defaults to FNV1a32 if not specified.
             */
            Algorithm alg_{Algorithm::FNV1a32};

            /**
             * @brief Convert Algorithm enum to C API string ID.
             *
             * Maps the Algorithm enum value to the corresponding string
             * identifier expected by the C API.
             *
             * @param alg Algorithm enum value.
             * @return C string representing the algorithm ID.
             */
            static const char* to_alg_str(Algorithm alg) {
                switch (alg) {
                    case Algorithm::FNV1a32:    return "fnv1a";
                    case Algorithm::FNV1a64:    return "fnv1a64";
                    case Algorithm::CRC32:      return "crc32";
                    case Algorithm::Murmur3_32: return "murmur3";
                    case Algorithm::Jenkins:    return "jenkins";
                    case Algorithm::SHA1:       return "sha1";
                    case Algorithm::SHA256:     return "sha256";
                    case Algorithm::SHA512:     return "sha512";
                    default:                    return "fnv1a";
                }
            }
        };

    } // namespace cryptic

} // namespace fossil

#endif

#endif /* FOSSIL_CRYPTIC_HASH_H */
