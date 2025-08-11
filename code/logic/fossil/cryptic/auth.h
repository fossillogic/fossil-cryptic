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

#include <stddef.h>
#include <stdint.h>

/* =======================
 *  HMAC (SHA-256 variant)
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
 * @param password  Pointer to the password bytes.
 * @param pass_len  Length of the password.
 * @param salt      Pointer to the salt bytes.
 * @param salt_len  Length of the salt.
 * @param iterations Number of iterations (recommended >= 100000).
 * @param out       Output buffer for derived key.
 * @param out_len   Length of the derived key.
 */
void fossil_cryptic_auth_pbkdf2_sha256(const uint8_t *password, size_t pass_len, const uint8_t *salt, size_t salt_len, uint32_t iterations, uint8_t *out, size_t out_len);

#ifdef __cplusplus
}
#include <string>
#include <vector>
#include <array>
#include <cstdint>
#include <cstring>

namespace fossil {

    namespace cryptic {



    } // namespace cryptic

} // namespace fossil

#endif

#endif /* FOSSIL_CRYPTIC_HASH_H */