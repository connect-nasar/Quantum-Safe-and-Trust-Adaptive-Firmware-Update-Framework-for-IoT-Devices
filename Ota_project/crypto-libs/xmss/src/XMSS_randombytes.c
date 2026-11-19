#include <limits.h>
#include <stdint.h>
#include <stdlib.h>

#include "XMSS_randombytes.h"

#if defined(ARDUINO_ARCH_ESP32) || defined(ESP_PLATFORM)

#include <esp_system.h>

void randombytes(unsigned char *x, unsigned long long xlen)
{
    while (xlen > 0) {
        size_t chunk = xlen > (unsigned long long)SIZE_MAX
                           ? SIZE_MAX
                           : (size_t)xlen;
        esp_fill_random(x, chunk);
        x += chunk;
        xlen -= chunk;
    }
}

#elif defined(_WIN32)

#include <windows.h>
#include <bcrypt.h>

void randombytes(unsigned char *x, unsigned long long xlen)
{
    while (xlen > 0) {
        ULONG chunk = xlen > (unsigned long long)ULONG_MAX
                          ? ULONG_MAX
                          : (ULONG)xlen;
        if (BCryptGenRandom(NULL, x, chunk, BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
            abort();
        }
        x += chunk;
        xlen -= chunk;
    }
}

#else

#include <stdio.h>

void randombytes(unsigned char *x, unsigned long long xlen)
{
    FILE *source = fopen("/dev/urandom", "rb");
    if (source == NULL) {
        abort();
    }

    while (xlen > 0) {
        size_t chunk = xlen > (unsigned long long)SIZE_MAX
                           ? SIZE_MAX
                           : (size_t)xlen;
        size_t received = fread(x, 1, chunk, source);
        if (received == 0) {
            fclose(source);
            abort();
        }
        x += received;
        xlen -= received;
    }

    fclose(source);
}

#endif
