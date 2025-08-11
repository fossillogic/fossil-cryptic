/*
 * -----------------------------------------------------------------------------
 * Project: Fossil Logic
 *
 * This file is part of the Fossil Logic project, which aims to develop high-
 * performance, cross-platform applications and libraries. The code contained
 * herein is subject to the terms and conditions defined in the project license.
 *
 * Author: Michael Gene Brockus (Dreamer)
 *
 * Copyright (C) 2024 Fossil Logic. All rights reserved.
 * -----------------------------------------------------------------------------
 */
#ifndef FOSSIL_CRYPTIC_HASH_H
#define FOSSIL_CRYPTIC_HASH_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---------------------
 * Types and constants
 * -------------------*/

/* Add in the enum */
typedef enum {
    FOSSIL_CRYPTIC_HASH_ALG_CRC32 = 1,
    FOSSIL_CRYPTIC_HASH_ALG_FNV1A32,
    FOSSIL_CRYPTIC_HASH_ALG_FNV1A64,
    FOSSIL_CRYPTIC_HASH_ALG_MURMUR3_32,
    FOSSIL_CRYPTIC_HASH_ALG_SHA256     /* NEW */
} fossil_cryptic_hash_alg_t;

/* SHA-256 context (internal, but exposed for size) */
typedef struct {
    uint32_t state[8];
    uint64_t bitlen;
    uint8_t  buffer[64];
} fossil_cryptic_hash_sha256_ctx_t;

/* Add to generic context union */
typedef struct {
    fossil_cryptic_hash_alg_t alg;
    union {
        uint32_t crc32;
        uint32_t fnv1a32;
        uint64_t fnv1a64;
        fossil_cryptic_hash_sha256_ctx_t sha256;
    } state;
} fossil_cryptic_hash_ctx_t;

// functions

/* --- One-shot SHA-256 --- */

/**
 * @brief Compute a SHA-256 digest for a complete data buffer in one call.
 *
 * This is a one-shot API — it processes the entire data block and produces
 * the 256-bit digest without maintaining a streaming context.
 *
 * @param data Pointer to the input data buffer.
 * @param len  Length of the input data in bytes.
 * @param out  Pointer to a 32-byte array where the resulting hash will be stored.
 */
void fossil_cryptic_hash_sha256(const void *data, size_t len, uint8_t out[32]);

/* --- Streaming SHA-256 --- */

/**
 * @brief Initialize a SHA-256 hashing context for incremental hashing.
 *
 * This function prepares the provided SHA-256 context for accepting data.
 * It must be called before any calls to fossil_cryptic_hash_sha256_update().
 *
 * @param ctx Pointer to a SHA-256 context structure.
 */
void fossil_cryptic_hash_sha256_init(fossil_cryptic_hash_sha256_ctx_t *ctx);

/**
 * @brief Feed data into the SHA-256 context.
 *
 * This function can be called multiple times to process data in chunks.
 * The context must have been initialized with fossil_cryptic_hash_sha256_init().
 *
 * @param ctx  Pointer to a SHA-256 context structure.
 * @param data Pointer to the data to be hashed.
 * @param len  Number of bytes of data to hash.
 */
void fossil_cryptic_hash_sha256_update(fossil_cryptic_hash_sha256_ctx_t *ctx, const void *data, size_t len);

/**
 * @brief Finalize the SHA-256 hash computation and produce the digest.
 *
 * Once this function is called, the context should not be reused unless
 * reinitialized. It writes the final 256-bit hash to the output buffer.
 *
 * @param ctx Pointer to the SHA-256 context structure.
 * @param out Pointer to a 32-byte array for storing the digest.
 */
void fossil_cryptic_hash_sha256_final(fossil_cryptic_hash_sha256_ctx_t *ctx, uint8_t out[32]);

/**
 * @brief Convert a 32-byte SHA-256 digest to a hexadecimal string.
 *
 * Produces a null-terminated, lowercase hexadecimal string representation
 * of the given digest. The destination buffer must be at least 65 bytes long.
 *
 * @param hash Pointer to the 32-byte SHA-256 digest.
 * @param dest Pointer to a buffer where the resulting hex string will be stored.
 */
void fossil_cryptic_hash_sha256_to_hex(const uint8_t hash[32], char dest[65]);


/* ---------------------
 * One-shot hashing APIs
 * -------------------*/

/**
 * @brief Compute a CRC32 checksum (IEEE 802.3 standard) for the given buffer.
 *
 * @param data Pointer to the input data buffer.
 * @param len  Length of the input data in bytes.
 * @return 32-bit CRC32 checksum.
 */
uint32_t fossil_cryptic_hash_crc32(const void *data, size_t len);

/**
 * @brief Compute an FNV-1a 32-bit hash for the given buffer.
 *
 * @param data Pointer to the input data buffer.
 * @param len  Length of the input data in bytes.
 * @return 32-bit FNV-1a hash.
 */
uint32_t fossil_cryptic_hash_fnv1a32(const void *data, size_t len);

/**
 * @brief Compute an FNV-1a 64-bit hash for the given buffer.
 *
 * @param data Pointer to the input data buffer.
 * @param len  Length of the input data in bytes.
 * @return 64-bit FNV-1a hash.
 */
uint64_t fossil_cryptic_hash_fnv1a64(const void *data, size_t len);

/**
 * @brief Compute a MurmurHash3 x86_32 hash for the given buffer.
 *
 * Uses the public-domain reference implementation. This algorithm is
 * non-cryptographic but provides good distribution for general-purpose use.
 *
 * @param data Pointer to the input data buffer.
 * @param len  Length of the input data in bytes.
 * @param seed Seed value to influence the hash result.
 * @return 32-bit MurmurHash3 value.
 */
uint32_t fossil_cryptic_hash_murmur3_32(const void *data, size_t len, uint32_t seed);


/* ---------------------
 * Streaming API (init/update/final)
 * Supports CRC32, FNV-1a (32/64), and SHA-256
 * -------------------*/

/**
 * @brief Initialize a generic hashing context for the specified algorithm.
 *
 * @param ctx Pointer to a generic hash context.
 * @param alg Algorithm identifier (from fossil_cryptic_hash_alg_t).
 */
void fossil_cryptic_hash_init(fossil_cryptic_hash_ctx_t *ctx, fossil_cryptic_hash_alg_t alg);

/**
 * @brief Feed data into a generic streaming hash context.
 *
 * This function may be called multiple times. The algorithm is determined
 * by the context initialization.
 *
 * @param ctx  Pointer to the generic hash context.
 * @param data Pointer to the input data to hash.
 * @param len  Length of the input data in bytes.
 */
void fossil_cryptic_hash_update(fossil_cryptic_hash_ctx_t *ctx, const void *data, size_t len);

/**
 * @brief Finalize and obtain a 32-bit hash result.
 *
 * Valid for algorithms that produce 32-bit results (CRC32, FNV1A32, Murmur3).
 *
 * @param ctx Pointer to the generic hash context.
 * @return 32-bit hash result.
 */
uint32_t fossil_cryptic_hash_final32(fossil_cryptic_hash_ctx_t *ctx);

/**
 * @brief Finalize and obtain a 64-bit hash result.
 *
 * Only valid if ctx->alg == FOSSIL_CRYPTIC_HASH_ALG_FNV1A64.
 *
 * @param ctx Pointer to the generic hash context.
 * @return 64-bit hash result.
 */
uint64_t fossil_cryptic_hash_final64(fossil_cryptic_hash_ctx_t *ctx);

/**
 * @brief Finalize a streaming SHA-256 computation from a generic context.
 *
 * This is the SHA-256 variant of the generic streaming API. It extracts
 * the final 256-bit digest into the output buffer.
 *
 * @param ctx Pointer to the generic hash context.
 * @param out Pointer to a 32-byte buffer for the resulting digest.
 */
void fossil_cryptic_hash_final_sha256(fossil_cryptic_hash_ctx_t *ctx, uint8_t out[32]);

/**
 * @brief Convert a 32-bit hash value to a lowercase hexadecimal string.
 *
 * The output buffer must be at least 9 bytes (8 hex digits + null terminator).
 *
 * @param h    32-bit hash value.
 * @param dest Pointer to the destination buffer.
 */
void fossil_cryptic_hash_u32_to_hex(uint32_t h, char dest[9]);

/**
 * @brief Convert a 64-bit hash value to a lowercase hexadecimal string.
 *
 * The output buffer must be at least 17 bytes (16 hex digits + null terminator).
 *
 * @param h    64-bit hash value.
 * @param dest Pointer to the destination buffer.
 */
void fossil_cryptic_hash_u64_to_hex(uint64_t h, char dest[17]);

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
         */
        class Hash {
        public:
            /// Supported algorithms
            enum class Algorithm : uint32_t {
                CRC32       = FOSSIL_CRYPTIC_HASH_ALG_CRC32,
                FNV1a32     = FOSSIL_CRYPTIC_HASH_ALG_FNV1A32,
                FNV1a64     = FOSSIL_CRYPTIC_HASH_ALG_FNV1A64,
                Murmur3_32  = FOSSIL_CRYPTIC_HASH_ALG_MURMUR3_32,
                SHA256      = FOSSIL_CRYPTIC_HASH_ALG_SHA256
            };
        
            /// Size of SHA-256 digest in bytes
            static constexpr size_t SHA256_SIZE = 32;
        
            /// Default constructor (no algorithm set)
            Hash() = default;
        
            /**
             * @brief Construct and initialize with a specific algorithm.
             * @param alg Algorithm to use.
             */
            explicit Hash(Algorithm alg) { init(alg); }
        
            /**
             * @brief Initialize the hash context for a given algorithm.
             * @param alg Algorithm to use.
             */
            void init(Algorithm alg) {
                fossil_cryptic_hash_init(&ctx_, static_cast<fossil_cryptic_hash_alg_t>(alg));
            }
        
            /**
             * @brief Feed data into the hash computation.
             * @param data Pointer to bytes.
             * @param len Number of bytes.
             */
            void update(const void* data, size_t len) {
                fossil_cryptic_hash_update(&ctx_, data, len);
            }
        
            /**
             * @brief Finalize and return a 32-bit result.
             * @return 32-bit hash.
             */
            uint32_t final32() {
                return fossil_cryptic_hash_final32(&ctx_);
            }
        
            /**
             * @brief Finalize and return a 64-bit result.
             * @return 64-bit hash.
             */
            uint64_t final64() {
                return fossil_cryptic_hash_final64(&ctx_);
            }
        
            /**
             * @brief Finalize SHA-256 and return the digest as a byte array.
             * @return std::array<uint8_t, 32> containing the digest.
             */
            std::array<uint8_t, SHA256_SIZE> finalSHA256() {
                std::array<uint8_t, SHA256_SIZE> out{};
                fossil_cryptic_hash_final_sha256(&ctx_, out.data());
                return out;
            }
        
            /**
             * @brief Convert a 32-bit hash value to a lowercase hex string.
             */
            static std::string to_hex(uint32_t h) {
                char buf[9];
                fossil_cryptic_hash_u32_to_hex(h, buf);
                return std::string(buf);
            }
        
            /**
             * @brief Convert a 64-bit hash value to a lowercase hex string.
             */
            static std::string to_hex(uint64_t h) {
                char buf[17];
                fossil_cryptic_hash_u64_to_hex(h, buf);
                return std::string(buf);
            }
        
            /**
             * @brief Convert a SHA-256 digest to lowercase hex.
             */
            static std::string to_hex(const std::array<uint8_t, SHA256_SIZE>& digest) {
                char buf[65];
                fossil_cryptic_hash_sha256_to_hex(digest.data(), buf);
                return std::string(buf);
            }
        
            /**
             * @brief One-shot SHA-256.
             */
            static std::array<uint8_t, SHA256_SIZE> sha256(const void* data, size_t len) {
                std::array<uint8_t, SHA256_SIZE> out{};
                fossil_cryptic_hash_sha256(data, len, out.data());
                return out;
            }
        
            /**
             * @brief One-shot SHA-256, hex output.
             */
            static std::string sha256Hex(const void* data, size_t len) {
                auto digest = sha256(data, len);
                return to_hex(digest);
            }
        
            /**
             * @brief One-shot CRC32.
             */
            static uint32_t crc32(const void* data, size_t len) {
                return fossil_cryptic_hash_crc32(data, len);
            }
        
            /**
             * @brief One-shot FNV-1a 32-bit.
             */
            static uint32_t fnv1a32(const void* data, size_t len) {
                return fossil_cryptic_hash_fnv1a32(data, len);
            }
        
            /**
             * @brief One-shot FNV-1a 64-bit.
             */
            static uint64_t fnv1a64(const void* data, size_t len) {
                return fossil_cryptic_hash_fnv1a64(data, len);
            }
        
            /**
             * @brief One-shot MurmurHash3 x86_32.
             */
            static uint32_t murmur3_32(const void* data, size_t len, uint32_t seed) {
                return fossil_cryptic_hash_murmur3_32(data, len, seed);
            }
        
        private:
            fossil_cryptic_hash_ctx_t ctx_{};
        };

    } // namespace cryptic

} // namespace fossil

#endif

#endif /* FOSSIL_CRYPTIC_HASH_H */
