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
#include "fossil/cryptic/cipher.h"
#include <stdint.h>
#include <string.h>

// ===========================================================
// Advanced XOR Cipher (with key schedule)
// ===========================================================
static void cipher_xor(const uint8_t* key, size_t key_len,
                       const uint8_t* input, uint8_t* output, size_t len) {
    // Simple key schedule: derive a pseudo-random stream from key
    uint32_t seed = 0xA5A5A5A5;
    for (size_t k = 0; k < key_len; ++k)
        seed ^= key[k] * 0x45D9F3B;
    for (size_t i = 0; i < len; i++) {
        seed = (seed ^ (seed << 13) ^ (seed >> 17)) + 0x9E3779B9;
        output[i] = input[i] ^ key[i % key_len] ^ ((seed >> (i % 24)) & 0xFF);
    }
}

// ===========================================================
// Morse Code Cipher (encode/decode)
// ===========================================================
static const char* morse_table[128] = {
    ['A'] = ".-",    ['B'] = "-...",  ['C'] = "-.-.",  ['D'] = "-..",
    ['E'] = ".",     ['F'] = "..-.",  ['G'] = "--.",   ['H'] = "....",
    ['I'] = "..",    ['J'] = ".---",  ['K'] = "-.-",   ['L'] = ".-..",
    ['M'] = "--",    ['N'] = "-.",    ['O'] = "---",   ['P'] = ".--.",
    ['Q'] = "--.-",  ['R'] = ".-.",   ['S'] = "...",   ['T'] = "-",
    ['U'] = "..-",   ['V'] = "...-",  ['W'] = ".--",   ['X'] = "-..-",
    ['Y'] = "-.--",  ['Z'] = "--..",
    ['0'] = "-----", ['1'] = ".----", ['2'] = "..---", ['3'] = "...--",
    ['4'] = "....-", ['5'] = ".....", ['6'] = "-....", ['7'] = "--...",
    ['8'] = "---..", ['9'] = "----.",
    [' '] = "/"
};

static void cipher_morse_encode(const uint8_t* input, uint8_t* output, size_t len) {
    size_t out_idx = 0;
    for (size_t i = 0; i < len; ++i) {
        char ch = input[i];
        if (ch >= 'a' && ch <= 'z') ch -= 32; // Convert to uppercase
        const char* code = morse_table[(unsigned char)ch];
        if (code) {
            size_t code_len = strlen(code);
            memcpy(output + out_idx, code, code_len);
            out_idx += code_len;
            output[out_idx++] = ' ';
        }
    }
    if (out_idx > 0) output[out_idx - 1] = '\0'; // Null-terminate
    else output[0] = '\0';
}

static void cipher_morse_decode(const uint8_t* input, uint8_t* output, size_t len) {
    size_t out_idx = 0;
    size_t i = 0;
    while (i < len) {
        // Find next space or end
        size_t start = i;
        while (i < len && input[i] != ' ') i++;
        size_t code_len = i - start;
        if (code_len > 0) {
            char code[8] = {0};
            memcpy(code, input + start, code_len);
            code[code_len] = '\0';
            char decoded = '?';
            for (int c = 0; c < 128; ++c) {
                if (morse_table[c] && strcmp(morse_table[c], code) == 0) {
                    decoded = (char)c;
                    break;
                }
            }
            output[out_idx++] = decoded;
        }
        i++; // Skip space
    }
    output[out_idx] = '\0';
}

//
// ===========================================================
// Advanced Caesar Cipher (with variable shift)
// ===========================================================
static void cipher_caesar(const uint8_t* key, size_t key_len,
                          const uint8_t* input, uint8_t* output, size_t len) {
    // Use key-derived shift value
    uint8_t shift = 0;
    for (size_t k = 0; k < key_len; ++k)
        shift ^= key[k];
    shift = (shift % 25) + 1; // Ensure shift is between 1 and 25

    for (size_t i = 0; i < len; ++i) {
        output[i] = input[i] + shift;
    }
}

static void cipher_caesar_decrypt(const uint8_t* key, size_t key_len,
                                  const uint8_t* input, uint8_t* output, size_t len) {
    uint8_t shift = 0;
    for (size_t k = 0; k < key_len; ++k)
        shift ^= key[k];
    shift = (shift % 25) + 1;

    for (size_t i = 0; i < len; ++i) {
        output[i] = input[i] - shift;
    }
}

// ===========================================================
// Advanced Vigenère Cipher (with key schedule)
// ===========================================================
static void cipher_vigenere(const uint8_t* key, size_t key_len,
                            const uint8_t* input, uint8_t* output, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        output[i] = input[i] + key[i % key_len];
    }
}

static void cipher_vigenere_decrypt(const uint8_t* key, size_t key_len,
                                    const uint8_t* input, uint8_t* output, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        output[i] = input[i] - key[i % key_len];
    }
}

// ===========================================================
// Advanced Feistel Cipher (multiple rounds, S-box)
// ===========================================================
static uint32_t feistel_sbox(uint32_t x) {
    // Simple non-linear S-box
    x = ((x >> 16) ^ x) * 0x45d9f3b;
    x = ((x >> 16) ^ x) * 0x45d9f3b;
    x = (x >> 16) ^ x;
    return x;
}

static uint32_t feistel_round(uint32_t half, uint32_t key, int round) {
    // Mix with S-box and round number
    return feistel_sbox(half ^ key ^ (0x9E3779B9 * round));
}

#define FEISTEL_ROUNDS 8

static void cipher_feistel_encrypt(uint8_t* data, size_t len, uint32_t key) {
    for (size_t i = 0; i + 8 <= len; i += 8) {
        uint32_t left, right;
        memcpy(&left, data + i, 4);
        memcpy(&right, data + i + 4, 4);
        for (int r = 0; r < FEISTEL_ROUNDS; r++) {
            uint32_t temp = right;
            right = left ^ feistel_round(right, key, r);
            left = temp;
        }
        memcpy(data + i, &left, 4);
        memcpy(data + i + 4, &right, 4);
    }
}

static void cipher_feistel_decrypt(uint8_t* data, size_t len, uint32_t key) {
    for (size_t i = 0; i + 8 <= len; i += 8) {
        uint32_t left, right;
        memcpy(&left, data + i, 4);
        memcpy(&right, data + i + 4, 4);
        for (int r = FEISTEL_ROUNDS - 1; r >= 0; r--) {
            uint32_t temp = left;
            left = right ^ feistel_round(left, key, r);
            right = temp;
        }
        memcpy(data + i, &left, 4);
        memcpy(data + i + 4, &right, 4);
    }
}

// ===========================================================
// Advanced Key Conversion Utility (FNV-1a + extra mixing)
// ===========================================================
static uint32_t key_to_u32(const char* key) {
    uint32_t hash = 0x811C9DC5;
    for (const char* p = key; *p; p++)
        hash = (hash ^ (uint8_t)*p) * 16777619u;
    // Extra mixing for advanced key schedule
    hash ^= (hash << 13);
    hash ^= (hash >> 7);
    hash ^= (hash << 17);
    return hash;
}

static uint64_t key_to_u64(const char* key) {
    uint64_t hash = 0xCBF29CE484222325ull;
    for (const char* p = key; *p; p++)
        hash = (hash ^ (uint8_t)*p) * 1099511628211ull;
    // Extra mixing for advanced key schedule
    hash ^= (hash << 21);
    hash ^= (hash >> 35);
    hash ^= (hash << 4);
    return hash;
}

// ===========================================================
// Main Entry Point (advanced selection and error handling)
// ===========================================================
int fossil_cryptic_cipher_compute(
    const char* algorithm,
    const char* mode,
    const char* bits,
    const char* key,
    const void* input, size_t input_len,
    void* output, size_t* output_len
) {
    if (!algorithm || !mode || !bits || !key || !input || !output || !output_len)
        return -1;

    int is_encrypt = 1;
    if (strcmp(mode, "decrypt") == 0) is_encrypt = 0;
    else if (strcmp(mode, "encrypt") == 0) is_encrypt = 1;
    else if (strcmp(mode, "auto") != 0) return -2;

    // Advanced key strength conversion
    uint32_t k32 = key_to_u32(key);

    // Algorithm selection (advanced: fallback and auto)
    if (strcmp(algorithm, "xor") == 0 || strcmp(algorithm, "auto") == 0) {
        cipher_xor((const uint8_t*)key, strlen(key),
                   (const uint8_t*)input, (uint8_t*)output, input_len);
        *output_len = input_len;
    }
    else if (strcmp(algorithm, "feistel") == 0) {
        if (is_encrypt)
            cipher_feistel_encrypt((uint8_t*)output, input_len, k32);
        else
            cipher_feistel_decrypt((uint8_t*)output, input_len, k32);
        *output_len = input_len;
    }
    else if (strcmp(algorithm, "caesar") == 0) {
        if (is_encrypt)
            cipher_caesar((const uint8_t*)key, strlen(key),
                          (const uint8_t*)input, (uint8_t*)output, input_len);
        else
            cipher_caesar_decrypt((const uint8_t*)key, strlen(key),
                                  (const uint8_t*)input, (uint8_t*)output, input_len);
        *output_len = input_len;
    }
    else if (strcmp(algorithm, "vigenere") == 0) {
        if (is_encrypt)
            cipher_vigenere((const uint8_t*)key, strlen(key),
                            (const uint8_t*)input, (uint8_t*)output, input_len);
        else
            cipher_vigenere_decrypt((const uint8_t*)key, strlen(key),
                                    (const uint8_t*)input, (uint8_t*)output, input_len);
        *output_len = input_len;
    }
    else if (strcmp(algorithm, "morse") == 0) {
        if (is_encrypt) {
            cipher_morse_encode((const uint8_t*)input, (uint8_t*)output, input_len);
            *output_len = strlen((const char*)output);
        } else {
            cipher_morse_decode((const uint8_t*)input, (uint8_t*)output, input_len);
            *output_len = strlen((const char*)output);
        }
    }
    else {
        // Advanced: fallback to XOR if unsupported algorithm
        cipher_xor((const uint8_t*)key, strlen(key),
                   (const uint8_t*)input, (uint8_t*)output, input_len);
        *output_len = input_len;
    }

    return 0;
}
