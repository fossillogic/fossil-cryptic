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
#include <string.h>
#include <limits.h>

#if defined(_WIN32)
#include <windows.h>
#elif defined(__linux__)
#include <sys/random.h>
#include <errno.h>
#else
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#endif

static int secure_random_bytes(uint8_t *out, size_t len)
{
#if defined(_WIN32)
    typedef LONG(WINAPI * BCryptGenRandom_t)(void *, PUCHAR, ULONG, ULONG);
    HMODULE bcrypt = LoadLibraryA("bcrypt.dll");
    if (!bcrypt)
        return -1;

    FARPROC gen_proc = GetProcAddress(bcrypt, "BCryptGenRandom");
    if (!gen_proc)
    {
        FreeLibrary(bcrypt);
        return -1;
    }

    BCryptGenRandom_t gen;
    memcpy(&gen, &gen_proc, sizeof(gen));

    size_t done = 0;
    while (done < len)
    {
        size_t remaining = len - done;
        ULONG chunk = (remaining > (size_t)ULONG_MAX) ? ULONG_MAX : (ULONG)remaining;
        /* BCRYPT_USE_SYSTEM_PREFERRED_RNG = 0x00000002 */
        if (gen(NULL, out + done, chunk, 0x00000002) < 0)
        {
            FreeLibrary(bcrypt);
            return -1;
        }
        done += chunk;
    }
    FreeLibrary(bcrypt);
    return 0;

#elif defined(__linux__)
    size_t done = 0;
    while (done < len)
    {
        ssize_t n = getrandom(out + done, len - done, 0);
        if (n > 0)
        {
            done += (size_t)n;
        }
        else if (n < 0 && errno == EINTR)
        {
            continue;
        }
        else
        {
            return -1;
        }
    }
    return 0;

#else
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0)
        return -1;

    size_t done = 0;
    while (done < len)
    {
        ssize_t n = read(fd, out + done, len - done);
        if (n > 0)
        {
            done += (size_t)n;
        }
        else if (n < 0 && errno == EINTR)
        {
            continue;
        }
        else
        {
            close(fd);
            return -1;
        }
    }
    close(fd);
    return 0;
#endif
}

int fossil_cryptic_rand_bytes(uint8_t *out, size_t len)
{
    if (!out || len == 0)
        return -1;
    return secure_random_bytes(out, len);
}
