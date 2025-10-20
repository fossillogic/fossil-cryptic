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
#ifndef FOSSIL_CRYPTIC_AUTH_H
#define FOSSIL_CRYPTIC_AUTH_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------------
 * Auth Core
 * ------------------------------------------------------------------------ */

/**
 * @brief Generate a salted password hash.
 *
 * @param password   The plain-text password.
 * @param salt       A random or fixed salt string (recommended 16+ chars).
 * @param alg        Hash algorithm ID (e.g. "fnv1a", "murmur3", etc.).
 * @param bit_pref   "u32", "u64", or "auto".
 * @param base_pref  "hex", "base64", or "auto".
 * @param out        Output buffer for encoded hash string.
 * @param outlen     Length of output buffer.
 * @return 0 on success, nonzero on error.
 */
int fossil_cryptic_auth_hash_password(const char *password,
                                      const char *salt,
                                      const char *alg,
                                      const char *bit_pref,
                                      const char *base_pref,
                                      char *out, size_t outlen);

/**
 * @brief Verify a password against a stored salted hash.
 *
 * @param password  Input password to verify.
 * @param salt      Salt used when generating the original hash.
 * @param expected  The stored hash string (previously produced).
 * @param alg       Algorithm ID.
 * @param bit_pref  "u32", "u64", or "auto".
 * @param base_pref "hex", "base64", or "auto".
 * @return 1 if valid match, 0 if not, negative on error.
 */
int fossil_cryptic_auth_verify_password(const char *password,
                                        const char *salt,
                                        const char *expected,
                                        const char *alg,
                                        const char *bit_pref,
                                        const char *base_pref);

/* ------------------------------------------------------------------------
 * Token-based Authentication (simple HMAC-like)
 * ------------------------------------------------------------------------ */

/**
 * @brief Generate a signed token using key and payload.
 *
 * Internally computes: hash(key + ":" + payload)
 *
 * @param key        Secret key string.
 * @param payload    Message or user token.
 * @param alg        Hash algorithm ID.
 * @param bit_pref   "u32", "u64", or "auto".
 * @param base_pref  "hex", "base64", or "auto".
 * @param out        Output buffer for encoded signature.
 * @param outlen     Output buffer size.
 * @return 0 on success, nonzero on error.
 */
int fossil_cryptic_auth_sign_token(const char *key,
                                   const char *payload,
                                   const char *alg,
                                   const char *bit_pref,
                                   const char *base_pref,
                                   char *out, size_t outlen);

/**
 * @brief Verify a token signature using the secret key.
 *
 * Recomputes hash(key + ":" + payload) and compares to expected signature.
 *
 * @return 1 if signature matches, 0 if not, negative on error.
 */
int fossil_cryptic_auth_verify_token(const char *key,
                                     const char *payload,
                                     const char *expected,
                                     const char *alg,
                                     const char *bit_pref,
                                     const char *base_pref);

/* ------------------------------------------------------------------------
 * Salt and Challenge Utilities
 * ------------------------------------------------------------------------ */

/**
 * @brief Generate a pseudo-random salt string (base64).
 *
 * @param out     Output buffer.
 * @param outlen  Output size (must be >= 16).
 * @return 0 on success, nonzero if RNG fails or buffer too small.
 */
int fossil_cryptic_auth_generate_salt(char *out, size_t outlen);

/**
 * @brief Generate a challenge string for handshake protocols.
 *
 * Combines timestamp + random + hash seed.
 *
 * @param out     Output buffer.
 * @param outlen  Output size.
 * @return 0 on success, nonzero otherwise.
 */
int fossil_cryptic_auth_generate_challenge(char *out, size_t outlen);

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
         * @brief Auth class provides C++ wrappers for cryptographic primitives.
         *
         * This class exposes static methods for password hashing/verification,
         * token signing/verification, salt/challenge generation, HMAC-SHA256,
         * PBKDF2-HMAC-SHA256, Poly1305, constant-time comparison, ChaCha20, and
         * ChaCha20-Poly1305 AEAD encryption/decryption.
         *
         * All methods wrap the corresponding C functions, providing convenient
         * C++ interfaces using std::array and std::vector for output buffers.
         */
        class Auth {
        public:
            // --- Password Hashing and Verification ---

            /**
             * @brief Generate a salted password hash.
             *
             * @param password   Plain-text password.
             * @param salt       Salt string.
             * @param alg        Hash algorithm ID.
             * @param bit_pref   "u32", "u64", or "auto".
             * @param base_pref  "hex", "base64", or "auto".
             * @return std::string containing the encoded hash, empty on error.
             */
            static std::string hash_password(const std::string& password,
                             const std::string& salt,
                             const std::string& alg,
                             const std::string& bit_pref,
                             const std::string& base_pref)
            {
            char out[128] = {0};
            int rc = fossil_cryptic_auth_hash_password(
                password.c_str(), salt.c_str(), alg.c_str(),
                bit_pref.c_str(), base_pref.c_str(), out, sizeof(out));
            return rc == 0 ? std::string(out) : std::string();
            }

            /**
             * @brief Verify a password against a stored salted hash.
             *
             * @return true if valid match, false otherwise.
             */
            static bool verify_password(const std::string& password,
                           const std::string& salt,
                           const std::string& expected,
                           const std::string& alg,
                           const std::string& bit_pref,
                           const std::string& base_pref)
            {
            int rc = fossil_cryptic_auth_verify_password(
                password.c_str(), salt.c_str(), expected.c_str(),
                alg.c_str(), bit_pref.c_str(), base_pref.c_str());
            return rc == 1;
            }

            // --- Token-based Authentication ---

            /**
             * @brief Generate a signed token using key and payload.
             *
             * @return std::string containing the encoded signature, empty on error.
             */
            static std::string sign_token(const std::string& key,
                          const std::string& payload,
                          const std::string& alg,
                          const std::string& bit_pref,
                          const std::string& base_pref)
            {
            char out[128] = {0};
            int rc = fossil_cryptic_auth_sign_token(
                key.c_str(), payload.c_str(), alg.c_str(),
                bit_pref.c_str(), base_pref.c_str(), out, sizeof(out));
            return rc == 0 ? std::string(out) : std::string();
            }

            /**
             * @brief Verify a token signature using the secret key.
             *
             * @return true if signature matches, false otherwise.
             */
            static bool verify_token(const std::string& key,
                         const std::string& payload,
                         const std::string& expected,
                         const std::string& alg,
                         const std::string& bit_pref,
                         const std::string& base_pref)
            {
            int rc = fossil_cryptic_auth_verify_token(
                key.c_str(), payload.c_str(), expected.c_str(),
                alg.c_str(), bit_pref.c_str(), base_pref.c_str());
            return rc == 1;
            }

            // --- Salt and Challenge Utilities ---

            /**
             * @brief Generate a pseudo-random salt string (base64).
             *
             * @param length Desired salt length (>= 16).
             * @return std::string containing the salt, empty on error.
             */
            static std::string generate_salt(size_t length = 24)
            {
            std::vector<char> out(length + 1, 0);
            int rc = fossil_cryptic_auth_generate_salt(out.data(), out.size());
            return rc == 0 ? std::string(out.data()) : std::string();
            }

            /**
             * @brief Generate a challenge string for handshake protocols.
             *
             * @param length Desired challenge length.
             * @return std::string containing the challenge, empty on error.
             */
            static std::string generate_challenge(size_t length = 32)
            {
            std::vector<char> out(length + 1, 0);
            int rc = fossil_cryptic_auth_generate_challenge(out.data(), out.size());
            return rc == 0 ? std::string(out.data()) : std::string();
            }

            // --- Crypto Primitives ---

            static std::array<uint8_t, 32> hmac_sha256(const uint8_t* key, size_t key_len, const uint8_t* data, size_t data_len) {
            std::array<uint8_t, 32> out;
            fossil_cryptic_auth_hmac_sha256(key, key_len, data, data_len, out.data());
            return out;
            }

            static std::vector<uint8_t> pbkdf2_sha256(const uint8_t* password, size_t pass_len, const uint8_t* salt, size_t salt_len, uint32_t iterations, size_t out_len) {
            std::vector<uint8_t> out(out_len);
            fossil_cryptic_auth_pbkdf2_sha256(password, pass_len, salt, salt_len, iterations, out.data(), out_len);
            return out;
            }

            static std::array<uint8_t, 16> poly1305_auth(const uint8_t key[32], const uint8_t* msg, size_t msg_len) {
            std::array<uint8_t, 16> tag;
            fossil_cryptic_auth_poly1305_auth(key, msg, msg_len, tag.data());
            return tag;
            }

            static void poly1305_init(fossil_cryptic_auth_poly1305_ctx_t* ctx, const uint8_t key[32]) {
            fossil_cryptic_auth_poly1305_init(ctx, key);
            }

            static void poly1305_update(fossil_cryptic_auth_poly1305_ctx_t* ctx, const uint8_t* msg, size_t msg_len) {
            fossil_cryptic_auth_poly1305_update(ctx, msg, msg_len);
            }

            static void poly1305_finish(fossil_cryptic_auth_poly1305_ctx_t* ctx, uint8_t tag[16]) {
            fossil_cryptic_auth_poly1305_finish(ctx, tag);
            }

            static bool consttime_equal(const uint8_t* a, const uint8_t* b, size_t len) {
            return fossil_cryptic_auth_consttime_equal(a, b, len) == 1;
            }

            static std::array<uint8_t, 64> chacha20_block(const uint8_t key[32], const uint8_t nonce[12], uint32_t counter) {
            std::array<uint8_t, 64> out;
            fossil_cryptic_auth_chacha20_block(key, nonce, counter, out.data());
            return out;
            }

            static std::vector<uint8_t> chacha20_xor(const uint8_t key[32], const uint8_t nonce[12], uint32_t counter, const uint8_t* in, size_t len) {
            std::vector<uint8_t> out(len);
            fossil_cryptic_auth_chacha20_xor(key, nonce, counter, in, out.data(), len);
            return out;
            }

            static std::vector<uint8_t> chacha20_poly1305_encrypt(const uint8_t key[32], const uint8_t nonce[12], const uint8_t* aad, size_t aad_len, const uint8_t* plaintext, size_t pt_len, uint8_t tag[16]) {
            std::vector<uint8_t> ciphertext(pt_len);
            fossil_cryptic_auth_chacha20_poly1305_encrypt(key, nonce, aad, aad_len, plaintext, pt_len, ciphertext.data(), tag);
            return ciphertext;
            }

            static std::vector<uint8_t> chacha20_poly1305_decrypt(const uint8_t key[32], const uint8_t nonce[12], const uint8_t* aad, size_t aad_len, const uint8_t* ciphertext, size_t ct_len, const uint8_t tag[16], bool& ok) {
            std::vector<uint8_t> plaintext(ct_len);
            ok = fossil_cryptic_auth_chacha20_poly1305_decrypt(key, nonce, aad, aad_len, ciphertext, ct_len, plaintext.data(), tag) == 1;
            return plaintext;
            }
        };

    } // namespace cryptic

} // namespace fossil

#endif

#endif /* FOSSIL_CRYPTIC_HASH_H */
