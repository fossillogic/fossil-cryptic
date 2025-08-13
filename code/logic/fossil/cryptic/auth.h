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
#ifndef FOSSIL_CRYPTIC_AUTH_H
#define FOSSIL_CRYPTIC_AUTH_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* =======================
 *  HMAC-SHA256
 * ======================= */

/**
 * @brief Computes HMAC-SHA256 for given data.
 *
 * @param key       Pointer to the key.
 * @param key_len   Length of the key in bytes.
 * @param data      Pointer to the message data.
 * @param data_len  Length of the message in bytes.
 * @param out       32-byte buffer for the resulting MAC.
 */
void fossil_cryptic_auth_hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len, uint8_t out[32]);

/* =======================
 *  PBKDF2-HMAC-SHA256
 * ======================= */

/**
 * @brief PBKDF2-HMAC-SHA256 password-based key derivation.
 *
 * @param password   Pointer to the password bytes.
 * @param pass_len   Length of the password.
 * @param salt       Pointer to the salt bytes.
 * @param salt_len   Length of the salt.
 * @param iterations Number of iterations (recommended >= 100000).
 * @param out        Output buffer for derived key.
 * @param out_len    Length of the derived key.
 */
void fossil_cryptic_auth_pbkdf2_sha256(const uint8_t *password, size_t pass_len, const uint8_t *salt, size_t salt_len, uint32_t iterations, uint8_t *out, size_t out_len);

/* =======================
 *  Poly1305 (one-shot)
 * ======================= */

/**
 * @brief Compute Poly1305 tag for a message using a 32-byte key.
 *
 * Key format: 32 bytes, lower 16 bytes are r (clamped), upper 16 bytes are s.
 * Output tag is 16 bytes.
 *
 * @param key     32-byte Poly1305 key
 * @param msg     Message bytes
 * @param msg_len Message length
 * @param tag     16-byte output tag
 */
void fossil_cryptic_auth_poly1305_auth(const uint8_t key[32], const uint8_t *msg, size_t msg_len, uint8_t tag[16]);

/* =======================
 *  Poly1305 streaming API
 * ======================= */

/**
 * @brief Opaque Poly1305 streaming context (small POD).
 *
 * You may reinitialize or reuse by calling fossil_cryptic_auth_poly1305_init().
 */
typedef struct {
    uint32_t r[5];        /* r as 5 26-bit limbs (clamped) */
    uint32_t h[5];        /* accumulator as 5 26-bit limbs */
    uint32_t pad[4];      /* s (128-bit) as four 32-bit words little-endian */
    size_t leftover;      /* bytes in buffer */
    uint8_t buffer[16];   /* partial block buffer */
} fossil_cryptic_auth_poly1305_ctx_t;

/**
 * @brief Initialize Poly1305 streaming context with 32-byte key.
 *
 * @param ctx  Pointer to context
 * @param key  32-byte key
 */
void fossil_cryptic_auth_poly1305_init(fossil_cryptic_auth_poly1305_ctx_t *ctx, const uint8_t key[32]);

/**
 * @brief Update Poly1305 context with message bytes.
 *
 * Can be called multiple times. Message is processed in 16-byte blocks internally.
 *
 * @param ctx     Pointer to context
 * @param msg     Message bytes
 * @param msg_len Length of message bytes
 */
void fossil_cryptic_auth_poly1305_update(fossil_cryptic_auth_poly1305_ctx_t *ctx, const uint8_t *msg, size_t msg_len);

/**
 * @brief Finalize Poly1305 and produce 16-byte tag.
 *
 * After finalize, ctx may be reused by calling init() again.
 *
 * @param ctx Pointer to context
 * @param tag 16-byte output tag
 */
void fossil_cryptic_auth_poly1305_finish(fossil_cryptic_auth_poly1305_ctx_t *ctx, uint8_t tag[16]);

/* =======================
 *  Utilities
 * ======================= */

/**
 * @brief Constant-time memory comparison.
 *
 * Returns 1 if equal, 0 otherwise. Runs in time dependent only on length.
 *
 * @param a   pointer to first buffer
 * @param b   pointer to second buffer
 * @param len length in bytes
 * @return 1 if equal, 0 if different
 */
int fossil_cryptic_auth_consttime_equal(const uint8_t *a, const uint8_t *b, size_t len);

/* ----------------------------
 * ChaCha20 core / stream XOR
 * ---------------------------- */

/**
 * @brief Compute a single 64-byte ChaCha20 block.
 *
 * @param key     32-byte key
 * @param nonce   12-byte nonce
 * @param counter 32-bit block counter (usually 0 for key block, 1..n for stream)
 * @param out     64-byte output block
 */
void fossil_cryptic_auth_chacha20_block(const uint8_t key[32], const uint8_t nonce[12], uint32_t counter, uint8_t out[64]);

/**
 * @brief XOR input with ChaCha20 keystream (encrypt/decrypt).
 *
 * Produces out[i] = in[i] ^ keystream[i], using the given counter as the
 * initial 32-bit block counter (keystream block 0 corresponds to counter).
 *
 * @param key      32-byte key
 * @param nonce    12-byte nonce
 * @param counter  initial 32-bit block counter (use 1 for AEAD encryption per RFC)
 * @param in       input bytes
 * @param out      output buffer (may alias in)
 * @param len      number of bytes to process
 */
void fossil_cryptic_auth_chacha20_xor(const uint8_t key[32], const uint8_t nonce[12], uint32_t counter, const uint8_t *in, uint8_t *out, size_t len);

/* ----------------------------
 * ChaCha20-Poly1305 AEAD
 * ---------------------------- */

/**
 * @brief Encrypt plaintext with ChaCha20-Poly1305 (IETF), producing ciphertext and 16-byte tag.
 *
 * @param key       32-byte key
 * @param nonce     12-byte nonce
 * @param aad       Additional authenticated data (may be NULL if aad_len == 0)
 * @param aad_len   Length of AAD
 * @param plaintext Plaintext bytes
 * @param pt_len    Length of plaintext
 * @param ciphertext Output buffer for ciphertext (must be at least pt_len). Can alias plaintext.
 * @param tag       16-byte output tag
 */
void fossil_cryptic_auth_chacha20_poly1305_encrypt(const uint8_t key[32], const uint8_t nonce[12], const uint8_t *aad, size_t aad_len, const uint8_t *plaintext, size_t pt_len, uint8_t *ciphertext, uint8_t tag[16]);

/**
 * @brief Decrypt ciphertext with ChaCha20-Poly1305 (IETF) and verify tag.
 *
 * @param key       32-byte key
 * @param nonce     12-byte nonce
 * @param aad       AAD bytes (may be NULL if aad_len == 0)
 * @param aad_len   Length of AAD
 * @param ciphertext Ciphertext bytes
 * @param ct_len    Length of ciphertext
 * @param plaintext Output buffer for plaintext (must be at least ct_len). May alias ciphertext.
 * @param tag       16-byte tag to verify
 * @return 1 on success (tag OK), 0 on failure (tag mismatch)
 */
int fossil_cryptic_auth_chacha20_poly1305_decrypt(const uint8_t key[32], const uint8_t nonce[12], const uint8_t *aad, size_t aad_len, const uint8_t *ciphertext, size_t ct_len, uint8_t *plaintext, const uint8_t tag[16]);

#ifdef __cplusplus
}
#include <string>
#include <vector>
#include <array>
#include <cstdint>
#include <cstring>

namespace fossil {

    namespace cryptic {

        class Auth {
        public:
            /**
             * @brief Computes HMAC-SHA256 for given data.
             *
             * @param key       Pointer to the key.
             * @param key_len   Length of the key in bytes.
             * @param data      Pointer to the message data.
             * @param data_len  Length of the message in bytes.
             * @param out       32-byte buffer for the resulting MAC.
             */
            static std::array<uint8_t, 32> hmac_sha256(const uint8_t* key, size_t key_len, const uint8_t* data, size_t data_len) {
                std::array<uint8_t, 32> out;
                fossil_cryptic_auth_hmac_sha256(key, key_len, data, data_len, out.data());
                return out;
            }

            /**
             * @brief Computes PBKDF2-HMAC-SHA256.
             *
             * @param password   Pointer to the password.
             * @param pass_len   Length of the password in bytes.
             * @param salt       Pointer to the salt.
             * @param salt_len   Length of the salt in bytes.
             * @param iterations Number of iterations.
             * @param out_len   Length of the output key in bytes.
             * @return Derived key.
             */
            static std::vector<uint8_t> pbkdf2_sha256(const uint8_t* password, size_t pass_len, const uint8_t* salt, size_t salt_len, uint32_t iterations, size_t out_len) {
                std::vector<uint8_t> out(out_len);
                fossil_cryptic_auth_pbkdf2_sha256(password, pass_len, salt, salt_len, iterations, out.data(), out_len);
                return out;
            }

            /**
             * @brief Computes Poly1305 MAC for given message.
             *
             * @param key       Pointer to the key.
             * @param msg      Pointer to the message data.
             * @param msg_len  Length of the message in bytes.
             * @return 16-byte Poly1305 tag.
             */
            static std::array<uint8_t, 16> poly1305_auth(const uint8_t key[32], const uint8_t* msg, size_t msg_len) {
                std::array<uint8_t, 16> tag;
                fossil_cryptic_auth_poly1305_auth(key, msg, msg_len, tag.data());
                return tag;
            }

        };

    } // namespace cryptic

} // namespace fossil

#endif

#endif /* FOSSIL_CRYPTIC_HASH_H */
