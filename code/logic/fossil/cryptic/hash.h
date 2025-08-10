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
void fossil_cryptic_hash_sha256(const void *data, size_t len, uint8_t out[32]);

/* --- Streaming SHA-256 --- */
void fossil_cryptic_hash_sha256_init(fossil_cryptic_hash_sha256_ctx_t *ctx);
void fossil_cryptic_hash_sha256_update(fossil_cryptic_hash_sha256_ctx_t *ctx, const void *data, size_t len);
void fossil_cryptic_hash_sha256_final(fossil_cryptic_hash_sha256_ctx_t *ctx, uint8_t out[32]);

/* Convenience: hex string for SHA-256 digest (dest must be at least 65 bytes) */
void fossil_cryptic_hash_sha256_to_hex(const uint8_t hash[32], char dest[65]);

/* ---------------------
 * One-shot hashing APIs
 * -------------------*/

/* CRC32 (IEEE 802.3) */
uint32_t fossil_cryptic_hash_crc32(const void *data, size_t len);

/* FNV-1a */
uint32_t  fossil_cryptic_hash_fnv1a32(const void *data, size_t len);
uint64_t  fossil_cryptic_hash_fnv1a64(const void *data, size_t len);

/* MurmurHash3 x86_32 (public-domain reference-style implementation) */
uint32_t  fossil_cryptic_hash_murmur3_32(const void *data, size_t len, uint32_t seed);

/* ---------------------
 * Streaming API (init/update/final)
 * Supports CRC32, FNV-1a (32/64)
 * -------------------*/

/* Initialize context for the requested algorithm */
void fossil_cryptic_hash_init(fossil_cryptic_hash_ctx_t *ctx, fossil_cryptic_hash_alg_t alg);

/* Feed bytes into the streaming hash */
void fossil_cryptic_hash_update(fossil_cryptic_hash_ctx_t *ctx, const void *data, size_t len);

/* Finalize and obtain 32-bit result. For 64-bit result, use final64 when appropriate. */
uint32_t fossil_cryptic_hash_final32(fossil_cryptic_hash_ctx_t *ctx);

/* Finalize and obtain 64-bit result. Only valid if ctx->alg == FNV1A64 */
uint64_t fossil_cryptic_hash_final64(fossil_cryptic_hash_ctx_t *ctx);

/* Convenience: compute hex string for a 32-bit value (dest must be at least 9 bytes) */
void fossil_cryptic_hash_u32_to_hex(uint32_t h, char dest[9]);

/* Convenience: compute hex string for a 64-bit value (dest must be at least 17 bytes) */
void fossil_cryptic_hash_u64_to_hex(uint64_t h, char dest[17]);

#ifdef __cplusplus
}
#include <stdexcept>
#include <vector>
#include <string>

namespace fossil {

namespace cryptic {



} // namespace cryptic

} // namespace fossil

#endif

#endif /* FOSSIL_CRYPTIC_HASH_H */
