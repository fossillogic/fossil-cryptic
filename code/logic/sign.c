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
#include "fossil/cryptic/sign.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

/* constant-time string compare: returns 1 if equal, 0 otherwise */
static int ct_equals(const char* a, const char* b) {
    if (!a || !b) return 0;
    size_t la = strlen(a), lb = strlen(b);
    if (la != lb) return 0;
    unsigned char diff = 0;
    for (size_t i = 0; i < la; ++i) diff |= (unsigned char)(a[i] ^ b[i]);
    return diff == 0;
}

/* Build signed-data = timestamp? "<ts>:" + input : input */
static int build_signed_data(const char* timestamp, const void* input, size_t input_len,
                             void** out_buf, size_t* out_len) {
    if (!out_buf || !out_len) return -1;
    *out_buf = NULL;
    *out_len = 0;

    if (!timestamp || strcmp(timestamp, "auto") == 0) {
        /* caller wants auto timestamp: create timestamp string */
        time_t now = time(NULL);
        char tsbuf[32];
        int n = snprintf(tsbuf, sizeof(tsbuf), "%lld", (long long)now);
        if (n <= 0) return -2;
        size_t tsl = (size_t)n;
        size_t total = tsl + 1 + input_len; /* ts + ':' + input */
        void* buf = malloc(total);
        if (!buf) return -3;
        memcpy(buf, tsbuf, tsl);
        ((char*)buf)[tsl] = ':';
        if (input_len) memcpy((char*)buf + tsl + 1, input, input_len);
        *out_buf = buf;
        *out_len = total;
        return 0;
    }

    if (timestamp[0] == '\0' || strcmp(timestamp, "none") == 0) {
        /* no timestamp - just copy input */
        if (input_len == 0) {
            void* buf = malloc(0);
            *out_buf = buf;
            *out_len = 0;
            return 0;
        }
        void* buf = malloc(input_len);
        if (!buf) return -3;
        memcpy(buf, input, input_len);
        *out_buf = buf;
        *out_len = input_len;
        return 0;
    }

    /* explicit timestamp provided */
    size_t tsl = strlen(timestamp);
    size_t total = tsl + 1 + input_len;
    void* buf = malloc(total);
    if (!buf) return -3;
    memcpy(buf, timestamp, tsl);
    ((char*)buf)[tsl] = ':';
    if (input_len) memcpy((char*)buf + tsl + 1, input, input_len);
    *out_buf = buf;
    *out_len = total;
    return 0;
}

int fossil_cryptic_sign(
    const char* algorithm,
    const char* bits,
    const char* base,
    const char* key,
    const void* input, size_t input_len,
    const char* timestamp,
    char* output, size_t output_len
) {
    if (!algorithm || !bits || !base || !key || !output) return -1;

    /* Build the data we will sign: either timestamped-data or raw input */
    void* signed_data = NULL;
    size_t signed_len = 0;
    int r = build_signed_data(timestamp, input, input_len, &signed_data, &signed_len);
    if (r != 0) return r;

    /* compute auth (this function prefixes the key internally according to your auth impl) */
    /* we will write signature into a temp buffer */
    size_t tmp_sig_len = 512; /* large enough for most signatures */
    char* tmp_sig = (char*)malloc(tmp_sig_len);
    if (!tmp_sig) { free(signed_data); return -4; }

    int auth_r = fossil_cryptic_auth_compute(algorithm, bits, base, key,
                                            signed_data, signed_len,
                                            tmp_sig, tmp_sig_len);
    if (auth_r != 0) { free(signed_data); free(tmp_sig); return -5; }

    /* construct final output: if timestamp used (NULL or "auto" or explicit ts not "none"/""), prefix ts */
    if (!timestamp || strcmp(timestamp, "auto") == 0) {
        /* need timestamp again - produce same timestamp string by reading from signed_data buffer */
        /* signed_data format: "<ts>:<input>" */
        char* colon = NULL;
        if (signed_len > 0) {
            colon = memchr(signed_data, ':', signed_len);
        }
        if (!colon) {
            /* unexpected, but fallback to signature only */
            if (strlen(tmp_sig) + 1 > output_len) { free(signed_data); free(tmp_sig); return -6; }
            strncpy(output, tmp_sig, output_len);
            output[output_len - 1] = '\0';
            free(signed_data); free(tmp_sig);
            return 0;
        }
        size_t tsl = (size_t)(colon - (char*)signed_data);
        size_t siglen = strlen(tmp_sig);
        size_t need = tsl + 1 + siglen + 1; /* ts + ':' + sig + NUL */
        if (need > output_len) { free(signed_data); free(tmp_sig); return -7; }
        memcpy(output, signed_data, tsl);
        output[tsl] = ':';
        memcpy(output + tsl + 1, tmp_sig, siglen);
        output[tsl + 1 + siglen] = '\0';
    } else if (timestamp[0] == '\0' || strcmp(timestamp, "none") == 0) {
        /* signature only */
        size_t siglen = strlen(tmp_sig);
        if (siglen + 1 > output_len) { free(signed_data); free(tmp_sig); return -7; }
        memcpy(output, tmp_sig, siglen);
        output[siglen] = '\0';
    } else {
        /* explicit timestamp string provided */
        size_t tsl = strlen(timestamp);
        size_t siglen = strlen(tmp_sig);
        size_t need = tsl + 1 + siglen + 1;
        if (need > output_len) { free(signed_data); free(tmp_sig); return -7; }
        memcpy(output, timestamp, tsl);
        output[tsl] = ':';
        memcpy(output + tsl + 1, tmp_sig, siglen);
        output[tsl + 1 + siglen] = '\0';
    }

    free(signed_data);
    free(tmp_sig);
    return 0;
}

int fossil_cryptic_check(
    const char* algorithm,
    const char* bits,
    const char* base,
    const char* key,
    const void* input, size_t input_len,
    const char* signature,
    int* ok_out
) {
    if (ok_out) *ok_out = 0;
    if (!algorithm || !bits || !base || !key || !signature) return -1;

    /* parse signature: optional "<ts>:<sig>" or "<sig>" */
    const char* colon = strchr(signature, ':');
    const char* sig_part = signature;
    char* ts_copy = NULL;
    if (colon) {
        size_t tsl = (size_t)(colon - signature);
        ts_copy = (char*)malloc(tsl + 1);
        if (!ts_copy) return -2;
        memcpy(ts_copy, signature, tsl);
        ts_copy[tsl] = '\0';
        sig_part = colon + 1;
    }

    /* Build signed_data using extracted timestamp (ts_copy) or no timestamp */
    void* signed_data = NULL;
    size_t signed_len = 0;
    int r = build_signed_data(ts_copy ? ts_copy : "none", input, input_len, &signed_data, &signed_len);
    if (r != 0) { free(ts_copy); return -3; }

    /* compute expected signature into temp buffer sized to be large enough for most signatures */
    size_t tmp_len = 512;
    char* tmp_sig = (char*)malloc(tmp_len);
    if (!tmp_sig) { free(signed_data); free(ts_copy); return -4; }

    int auth_r = fossil_cryptic_auth_compute(algorithm, bits, base, key,
                                            signed_data, signed_len,
                                            tmp_sig, tmp_len);
    if (auth_r != 0) { free(signed_data); free(ts_copy); free(tmp_sig); return -5; }

    /* compare provided signature (sig_part) to computed tmp_sig in constant time */
    int equal = ct_equals(sig_part, tmp_sig);

    if (ok_out) *ok_out = equal ? 1 : 0;

    free(signed_data);
    free(ts_copy);
    free(tmp_sig);

    return equal ? 0 : 1;
}
