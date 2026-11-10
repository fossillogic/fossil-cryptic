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
#include "fossil/cryptic/rand.h"
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stddef.h>

#if defined(_WIN32)
#include <windows.h>
#else
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#endif

// ===========================================================
// Operating-system cryptographic entropy
// ===========================================================
static int secure_random_bytes(uint8_t* out, size_t len) {
#if defined(_WIN32)
    typedef LONG (WINAPI *bcrypt_gen_random_fn)(void*, unsigned char*, ULONG, ULONG);
    HMODULE bcrypt = LoadLibraryA("bcrypt.dll");
    if (!bcrypt) return -1;

    FARPROC proc = GetProcAddress(bcrypt, "BCryptGenRandom");
    if (!proc) {
        FreeLibrary(bcrypt);
        return -1;
    }
    bcrypt_gen_random_fn gen_random = NULL;
    memcpy(&gen_random, &proc, sizeof(gen_random));

    /* BCRYPT_USE_SYSTEM_PREFERRED_RNG */
    LONG status = gen_random(NULL, out, (ULONG)len, 0x00000002);
    FreeLibrary(bcrypt);
    return status >= 0 ? 0 : -1;
#else
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return -1;

    size_t done = 0;
    while (done < len) {
        ssize_t n = read(fd, out + done, len - done);
        if (n > 0) {
            done += (size_t)n;
        } else if (n < 0 && errno == EINTR) {
            continue;
        } else {
            close(fd);
            return -1;
        }
    }

    close(fd);
    return 0;
#endif
}

// ===========================================================
// Base64 + Hex encoding helpers
// ===========================================================
static const char base64_chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static void encode_base64(const uint8_t* data, size_t len, char* out) {
    size_t i = 0, j = 0;
    while (i < len) {
        size_t remaining = len - i;
        uint32_t a = data[i++];
        uint32_t b = remaining > 1 ? data[i++] : 0;
        uint32_t c = remaining > 2 ? data[i++] : 0;
        uint32_t triple = (a << 16) | (b << 8) | c;

        out[j++] = base64_chars[(triple >> 18) & 0x3F];
        out[j++] = base64_chars[(triple >> 12) & 0x3F];
        out[j++] = remaining > 1 ? base64_chars[(triple >> 6) & 0x3F] : '=';
        out[j++] = remaining > 2 ? base64_chars[triple & 0x3F] : '=';
    }
    out[j] = '\0';
}

// ===========================================================
// Main Entry Point
// ===========================================================
int fossil_cryptic_rand_compute(
    const char* algorithm,
    const char* bits,
    const char* base,
    const char* seed,
    char* output, size_t output_len
) {
    if (!algorithm || !bits || !base || !output) return -1;

    /* Legacy algorithm names remain accepted, but all use OS CSPRNG entropy. */
    if (strcmp(algorithm, "auto") != 0 && strcmp(algorithm, "csprng") != 0 &&
        strcmp(algorithm, "secure") != 0 && strcmp(algorithm, "lcg") != 0 &&
        strcmp(algorithm, "xor") != 0 && strcmp(algorithm, "mix") != 0)
        return -2;

    int use64;
    if (strcmp(bits, "u64") == 0) use64 = 1;
    else if (strcmp(bits, "u32") == 0) use64 = 0;
    else if (strcmp(bits, "auto") == 0) use64 = (sizeof(void*) == 8);
    else return -1;

    size_t len = use64 ? 8 : 4;
    uint8_t random_bytes[8];
    (void)seed; /* A caller-provided seed must not weaken or determine randomness. */
    if (secure_random_bytes(random_bytes, len) != 0) return -4;

    // Encode output
    if (strcmp(base, "hex") == 0 || strcmp(base, "auto") == 0) {
        if (output_len < len * 2 + 1) return -5;
        for (size_t i = 0; i < len; ++i)
            snprintf(output + i * 2, output_len - i * 2, "%02x", random_bytes[i]);
    }
    else if (strcmp(base, "base64") == 0) {
        size_t encoded_len = 4 * ((len + 2) / 3);
        if (output_len < encoded_len + 1) return -5;
        encode_base64(random_bytes, len, output);
    }
    else {
        return -3; // unsupported base
    }

    return 0;
}
