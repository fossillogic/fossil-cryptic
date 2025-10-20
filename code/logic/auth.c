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
#include "fossil/cryptic/auth.h"
#include "fossil/cryptic/hash.h"
#include <string.h>
#include <stdio.h>
#include <time.h>

/* Enhanced fallback RNG (non-crypto, portable, seeded) */
static uint32_t fossil_rand32(void) {
    static uint32_t s = 0;
    if (s == 0) {
        s = (uint32_t)time(NULL) ^ (uint32_t)(uintptr_t)&s;
    }
    s ^= s << 13;
    s ^= s >> 17;
    s ^= s << 5;
    return s;
}

static void fossil_fill_rand_bytes(uint8_t *buf, size_t n) {
    for (size_t i = 0; i < n; ++i)
        buf[i] = (uint8_t)(fossil_rand32() & 0xFF);
}

/* ------------------------------------------------------------------------
 * Salt and Challenge
 * ------------------------------------------------------------------------ */

int fossil_cryptic_auth_generate_salt(char *out, size_t outlen) {
    if (!out || outlen < 16) return -1;
    uint8_t tmp[16];
    fossil_fill_rand_bytes(tmp, sizeof(tmp));
    if (fossil_cryptic_hash_to_str(tmp, sizeof(tmp), "fnv1a64", "u64", "base64", out, outlen) != 0)
        return -2;
    return 0;
}

int fossil_cryptic_auth_generate_challenge(char *out, size_t outlen) {
    if (!out || outlen < 24) return -1;
    char salt[32];
    if (fossil_cryptic_auth_generate_salt(salt, sizeof(salt)) != 0)
        return -2;
    char timebuf[32];
    snprintf(timebuf, sizeof(timebuf), "%lu", (unsigned long)time(NULL));

    char combined[128];
    snprintf(combined, sizeof(combined), "%s:%s", timebuf, salt);

    if (fossil_cryptic_hash_to_str(combined, strlen(combined),
                                   "murmur3", "auto", "base64",
                                   out, outlen) != 0)
        return -3;
    return 0;
}

/* ------------------------------------------------------------------------
 * Password Hashing
 * ------------------------------------------------------------------------ */

int fossil_cryptic_auth_hash_password(const char *password,
                                      const char *salt,
                                      const char *alg,
                                      const char *bit_pref,
                                      const char *base_pref,
                                      char *out, size_t outlen)
{
    if (!password || !salt || !out) return -1;
    char combined[512];
    snprintf(combined, sizeof(combined), "%s:%s", salt, password);
    return fossil_cryptic_hash_to_str(combined, strlen(combined),
                                      alg, bit_pref, base_pref,
                                      out, outlen);
}

int fossil_cryptic_auth_verify_password(const char *password,
                                        const char *salt,
                                        const char *expected,
                                        const char *alg,
                                        const char *bit_pref,
                                        const char *base_pref)
{
    if (!password || !salt || !expected) return -1;
    char computed[128];
    if (fossil_cryptic_auth_hash_password(password, salt, alg, bit_pref, base_pref,
                                          computed, sizeof(computed)) != 0)
        return -2;
    return strcmp(expected, computed) == 0 ? 1 : 0;
}

/* ------------------------------------------------------------------------
 * Token Signing
 * ------------------------------------------------------------------------ */

int fossil_cryptic_auth_sign_token(const char *key,
                                   const char *payload,
                                   const char *alg,
                                   const char *bit_pref,
                                   const char *base_pref,
                                   char *out, size_t outlen)
{
    if (!key || !payload || !out) return -1;
    char combined[512];
    snprintf(combined, sizeof(combined), "%s:%s", key, payload);
    return fossil_cryptic_hash_to_str(combined, strlen(combined),
                                      alg, bit_pref, base_pref,
                                      out, outlen);
}

int fossil_cryptic_auth_verify_token(const char *key,
                                     const char *payload,
                                     const char *expected,
                                     const char *alg,
                                     const char *bit_pref,
                                     const char *base_pref)
{
    if (!key || !payload || !expected) return -1;
    char computed[128];
    if (fossil_cryptic_auth_sign_token(key, payload, alg, bit_pref, base_pref,
                                       computed, sizeof(computed)) != 0)
        return -2;
    return strcmp(expected, computed) == 0 ? 1 : 0;
}
