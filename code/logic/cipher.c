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
#include "fossil/cryptic/cipher.h"
#include <string.h>
#include <ctype.h>

int fossil_cryptic_cipher_xor(
    const uint8_t *key, size_t key_len,
    const uint8_t *in, size_t in_len,
    uint8_t *out)
{
    if (!key || !in || !out || key_len == 0) return -1;
    for (size_t i = 0; i < in_len; i++)
        out[i] = in[i] ^ key[i % key_len];
    return 0;
}

int fossil_cryptic_cipher_caesar(
    int shift,
    const uint8_t *in, size_t in_len,
    uint8_t *out)
{
    if (!in || !out) return -1;
    shift %= 26;
    if (shift < 0) shift += 26;

    for (size_t i = 0; i < in_len; i++) {
        uint8_t c = in[i];
        if (c >= 'A' && c <= 'Z')
            out[i] = (uint8_t)('A' + (c - 'A' + shift) % 26);
        else if (c >= 'a' && c <= 'z')
            out[i] = (uint8_t)('a' + (c - 'a' + shift) % 26);
        else
            out[i] = c;
    }
    return 0;
}

int fossil_cryptic_cipher_vigenere(
    const char *key,
    int encrypt,
    const uint8_t *in, size_t in_len,
    uint8_t *out)
{
    if (!key || !in || !out || key[0] == '\0') return -1;

    size_t key_len = strlen(key);
    size_t ki = 0;

    for (size_t i = 0; i < in_len; i++) {
        uint8_t c = in[i];
        if (isalpha(c)) {
            int base = isupper(c) ? 'A' : 'a';
            int k = toupper((unsigned char)key[ki % key_len]) - 'A';
            if (!encrypt) k = -k;
            out[i] = (uint8_t)(base + (c - base + k + 26) % 26);
            ki++;
        } else {
            out[i] = c;
        }
    }
    return 0;
}
