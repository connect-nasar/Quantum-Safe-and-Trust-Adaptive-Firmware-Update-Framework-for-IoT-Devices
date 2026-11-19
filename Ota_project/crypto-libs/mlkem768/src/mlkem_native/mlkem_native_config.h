#ifndef MLK_ESP32_CONFIG_H
#define MLK_ESP32_CONFIG_H

#include <esp_system.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#define MLK_CONFIG_NAMESPACE_PREFIX MLKEM768
#define MLK_CONFIG_FIPS202_CUSTOM_HEADER "arduino_fips202.h"
#define MLK_CONFIG_SERIAL_FIPS202_ONLY
#define MLK_CONFIG_CUSTOM_RANDOMBYTES
#define MLK_CONFIG_NO_ASM
#define MLK_CONFIG_CUSTOM_ZEROIZE
#define MLK_CONFIG_CUSTOM_ALLOC_FREE

#define MLK_CUSTOM_ALLOC(variable, type, count) \
    type *variable = (type *)malloc(sizeof(type) * (count))
#define MLK_CUSTOM_FREE(variable, type, count) \
    free(variable)

static inline void mlk_zeroize(void *ptr, size_t len)
{
    volatile uint8_t *barrier = (volatile uint8_t *)ptr;
    while (len-- != 0) {
        *barrier++ = 0;
    }
}

static inline int mlk_randombytes(uint8_t *out, size_t outlen)
{
    esp_fill_random(out, outlen);
    return 0;
}

#endif
