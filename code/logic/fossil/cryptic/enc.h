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
#ifndef FOSSIL_CRYPTIC_ENC_H
#define FOSSIL_CRYPTIC_ENC_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------
 * Utility
 * ------------------------*/

/**
 * @brief Securely zero memory (attempts to avoid being optimized away).
 *
 * @param p pointer to memory
 * @param n number of bytes
 */
void fossil_cryptic_enc_secure_zero(void *p, size_t n);

/* -------------------------
 * ChaCha20-CTR (wrapper)
 * ------------------------*/

/**
 * @brief ChaCha20-CTR XOR (convenience wrapper).
 *
 * Produces out[i] = in[i] ^ keystream[i] starting at the provided counter.
 * This calls the chacha20 xor primitive in the auth sub-library.
 *
 * @param key 32-byte key
 * @param nonce 12-byte nonce
 * @param counter 32-bit initial block counter
 * @param in input bytes
 * @param out output buffer (may alias in)
 * @param len bytes
 */
void fossil_cryptic_enc_chacha20_ctr_xor(const uint8_t key[32], const uint8_t nonce[12], uint32_t counter, const uint8_t *in, uint8_t *out, size_t len);

/* -------------------------
 * ChaCha20-Poly1305 AEAD wrapper
 * ------------------------*/

/**
 * @brief AEAD encrypt (ChaCha20-Poly1305).
 *
 * This is a thin wrapper around the auth sub-library function but kept
 * in the encryption API for discoverability.
 */
void fossil_cryptic_enc_chacha20_poly1305_encrypt(const uint8_t key[32], const uint8_t nonce[12], const uint8_t *aad, size_t aad_len, const uint8_t *plaintext, size_t pt_len, uint8_t *ciphertext, uint8_t tag[16]);

/**
 * @brief AEAD decrypt (ChaCha20-Poly1305).
 *
 * Returns 1 on success (tag verified), 0 on tag mismatch.
 */
int fossil_cryptic_enc_chacha20_poly1305_decrypt(const uint8_t key[32], const uint8_t nonce[12], const uint8_t *aad, size_t aad_len, const uint8_t *ciphertext, size_t ct_len, uint8_t *plaintext, const uint8_t tag[16]);

/* -------------------------
 * AES-CTR + HMAC-SHA256 (Encrypt-then-MAC)
 * ------------------------*/

/**
 * @brief AES key sizes supported (AES-128 only for now).
 */
typedef enum {
    FOSSIL_CRYPTIC_ENC_AES_128 = 128,
    /* future: AES_256 */
} fossil_cryptic_enc_aes_keybits_t;

/**
 * @brief AES-CTR Encrypt-then-MAC (HMAC-SHA256).
 *
 * - Encrypts plaintext with AES-CTR using provided 128-bit key and 16-byte IV (counter block).
 * - Computes HMAC-SHA256 over: aad || ciphertext || uint64_be(aad_len) || uint64_be(ct_len)
 * - Writes tag (32 bytes) to mac_out.
 *
 * Note: AES primitive is internal and AES-128 only currently.
 *
 * @param key 16-byte AES key
 * @param iv 16-byte IV (counter block; CTR increments low 64 bits or whole counter per implementation)
 * @param aad additional authenticated data (may be NULL if aad_len == 0)
 * @param aad_len length of aad
 * @param plaintext plaintext bytes
 * @param pt_len length
 * @param ciphertext output buffer (may alias plaintext)
 * @param mac_out 32-byte output MAC (HMAC-SHA256)
 */
void fossil_cryptic_enc_aes128_ctr_encrypt_then_mac_hmac_sha256(const uint8_t key[16], const uint8_t iv[16], const uint8_t *aad, size_t aad_len, const uint8_t *plaintext, size_t pt_len, uint8_t *ciphertext, uint8_t mac_out[32]);

/**
 * @brief Verify and decrypt AES-CTR + HMAC-SHA256 (Encrypt-then-MAC).
 *
 * Returns 1 if tag valid and plaintext written; 0 if tag invalid (plaintext not written).
 *
 * @param key 16-byte AES key
 * @param iv 16-byte IV
 * @param aad aad bytes
 * @param aad_len length
 * @param ciphertext ciphertext bytes
 * @param ct_len length
 * @param plaintext out buffer (must be at least ct_len). May alias ciphertext.
 * @param mac_in 32-byte tag to verify
 * @return 1 on success, 0 on failure
 */
int fossil_cryptic_enc_aes128_ctr_verify_then_decrypt_hmac_sha256(const uint8_t key[16], const uint8_t iv[16], const uint8_t *aad, size_t aad_len, const uint8_t *ciphertext, size_t ct_len, uint8_t *plaintext, const uint8_t mac_in[32]);

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
         * @brief C++ Encryptor utility class for Fossil Cryptic encryption APIs.
         *
         * Provides static wrappers for secure zeroing, ChaCha20, and AES-128-CTR
         * encryption/decryption functions.
         */
        class Encryptor
        {
        public:
            /**
             * @brief Securely zero memory.
             *
             * @param p Pointer to memory.
             * @param n Number of bytes.
             */
            static void secure_zero(void *p, size_t n) {
                fossil_cryptic_enc_secure_zero(p, n);
            }

            /**
             * @brief ChaCha20-CTR XOR.
             *
             * @param key 32-byte key.
             * @param nonce 12-byte nonce.
             * @param counter Initial block counter.
             * @param in Input bytes.
             * @param out Output buffer.
             * @param len Number of bytes.
             */
            static void chacha20_ctr_xor(
                const std::array<uint8_t, 32> &key,
                const std::array<uint8_t, 12> &nonce,
                uint32_t counter,
                const uint8_t *in,
                uint8_t *out,
                size_t len) {
                fossil_cryptic_enc_chacha20_ctr_xor(key.data(), nonce.data(), counter, in, out, len);
            }

            /**
             * @brief ChaCha20-Poly1305 AEAD encrypt.
             *
             * @param key 32-byte key.
             * @param nonce 12-byte nonce.
             * @param aad Additional authenticated data.
             * @param aad_len Length of aad.
             * @param plaintext Input plaintext.
             * @param pt_len Plaintext length.
             * @param ciphertext Output ciphertext buffer.
             * @param tag Output tag (16 bytes).
             */
            static void chacha20_poly1305_encrypt(
                const std::array<uint8_t, 32> &key,
                const std::array<uint8_t, 12> &nonce,
                const uint8_t *aad,
                size_t aad_len,
                const uint8_t *plaintext,
                size_t pt_len,
                uint8_t *ciphertext,
                std::array<uint8_t, 16> &tag) {
                fossil_cryptic_enc_chacha20_poly1305_encrypt(
                    key.data(), nonce.data(), aad, aad_len, plaintext, pt_len, ciphertext, tag.data());
            }

            /**
             * @brief ChaCha20-Poly1305 AEAD decrypt.
             *
             * @param key 32-byte key.
             * @param nonce 12-byte nonce.
             * @param aad Additional authenticated data.
             * @param aad_len Length of aad.
             * @param ciphertext Input ciphertext.
             * @param ct_len Ciphertext length.
             * @param plaintext Output plaintext buffer.
             * @param tag Tag to verify (16 bytes).
             * @return true if tag is valid, false otherwise.
             */
            static bool chacha20_poly1305_decrypt(
                const std::array<uint8_t, 32> &key,
                const std::array<uint8_t, 12> &nonce,
                const uint8_t *aad,
                size_t aad_len,
                const uint8_t *ciphertext,
                size_t ct_len,
                uint8_t *plaintext,
                const std::array<uint8_t, 16> &tag) {
                return fossil_cryptic_enc_chacha20_poly1305_decrypt(
                           key.data(), nonce.data(), aad, aad_len, ciphertext, ct_len, plaintext, tag.data()) == 1;
            }

            /**
             * @brief AES-128-CTR Encrypt-then-MAC (HMAC-SHA256).
             *
             * @param key 16-byte AES key.
             * @param iv 16-byte IV.
             * @param aad Additional authenticated data.
             * @param aad_len Length of aad.
             * @param plaintext Input plaintext.
             * @param pt_len Plaintext length.
             * @param ciphertext Output ciphertext buffer.
             * @param mac_out Output MAC (32 bytes).
             */
            static void aes128_ctr_encrypt_then_mac_hmac_sha256(
                const std::array<uint8_t, 16> &key,
                const std::array<uint8_t, 16> &iv,
                const uint8_t *aad,
                size_t aad_len,
                const uint8_t *plaintext,
                size_t pt_len,
                uint8_t *ciphertext,
                std::array<uint8_t, 32> &mac_out) {
                fossil_cryptic_enc_aes128_ctr_encrypt_then_mac_hmac_sha256(
                    key.data(), iv.data(), aad, aad_len, plaintext, pt_len, ciphertext, mac_out.data());
            }

            /**
             * @brief AES-128-CTR Verify-then-Decrypt (HMAC-SHA256).
             *
             * @param key 16-byte AES key.
             * @param iv 16-byte IV.
             * @param aad Additional authenticated data.
             * @param aad_len Length of aad.
             * @param ciphertext Input ciphertext.
             * @param ct_len Ciphertext length.
             * @param plaintext Output plaintext buffer.
             * @param mac_in Input MAC (32 bytes).
             * @return true if tag is valid and decryption succeeded, false otherwise.
             */
            static bool aes128_ctr_verify_then_decrypt_hmac_sha256(
                const std::array<uint8_t, 16> &key,
                const std::array<uint8_t, 16> &iv,
                const uint8_t *aad,
                size_t aad_len,
                const uint8_t *ciphertext,
                size_t ct_len,
                uint8_t *plaintext,
                const std::array<uint8_t, 32> &mac_in) {
                return fossil_cryptic_enc_aes128_ctr_verify_then_decrypt_hmac_sha256(
                           key.data(), iv.data(), aad, aad_len, ciphertext, ct_len, plaintext, mac_in.data()) == 1;
            }
        };

    } // namespace cryptic

} // namespace fossil

#endif

#endif /* FOSSIL_CRYPTIC_HASH_H */
