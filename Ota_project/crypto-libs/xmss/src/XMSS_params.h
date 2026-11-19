#ifndef XMSS_PARAMS_H
#define XMSS_PARAMS_H

#include <stdint.h>
#include "XMSS_config.h"

/* Names expected by the existing hash implementation. */
#define XMSS_SHA2       XMSS_HASH_SHA2
#define XMSS_SHAKE128   XMSS_HASH_SHAKE128
#define XMSS_SHAKE256   XMSS_HASH_SHAKE256

// #define XMSS_OID_LEN 0

/* Parameters selected by XMSS_MODE. */
#define XMSS_N              XMSS_CFG_N
#define XMSS_PADDING_LEN    XMSS_CFG_PADDING
#define XMSS_FULL_HEIGHT    XMSS_CFG_HEIGHT
#define XMSS_TREE_HEIGHT    XMSS_CFG_TREE_HEIGHT
#define XMSS_D              XMSS_CFG_D
#define XMSS_WOTS_W         XMSS_CFG_WOTS_W
#define XMSS_BDS_K          XMSS_CFG_BDS_K

/* Compile-time validation for the current supported scope. */
#if (XMSS_D != 1) && (XMSS_D != 2)
#error "Current modes support only D=1 or D=2"
#endif

#if (XMSS_TREE_HEIGHT != 10) && (XMSS_TREE_HEIGHT != 20)
#error "Current modes support only tree height 10 or 20"
#endif

#if XMSS_FULL_HEIGHT != (XMSS_TREE_HEIGHT * XMSS_D)
#error "Invalid full-height configuration"
#endif

#if (XMSS_N != 32) && (XMSS_N != 64)
#error "Current modes support only n=32 or n=64"
#endif

/*
 * WOTS+ w is fixed to 16 for all current modes.
 */
#if XMSS_WOTS_W != 16
#error "The current standard-profile modes require WOTS+ w=16"
#endif

#if XMSS_BDS_K >= XMSS_TREE_HEIGHT
#error "XMSS_BDS_K must be smaller than XMSS_TREE_HEIGHT"
#endif

#if ((XMSS_TREE_HEIGHT - XMSS_BDS_K) % 2) != 0
#error "XMSS_TREE_HEIGHT - XMSS_BDS_K must be even"
#endif

/* WOTS+ parameters for w=16. */
#define XMSS_WOTS_LOG_W 4

#define XMSS_WOTS_LEN1 \
    ((8 * XMSS_N) / XMSS_WOTS_LOG_W)

#define XMSS_WOTS_LEN2 3

#define XMSS_WOTS_LEN \
    (XMSS_WOTS_LEN1 + XMSS_WOTS_LEN2)

#define XMSS_WOTS_SIG_BYTES \
    (XMSS_WOTS_LEN * XMSS_N)

/*
 * XMSS uses a four-byte index.
 * XMSSMT uses enough bytes to represent the full tree height.
 */
#if XMSS_D == 1
#define XMSS_INDEX_BYTES 4
#else
#define XMSS_INDEX_BYTES ((XMSS_FULL_HEIGHT + 7) / 8)
#endif

#define XMSS_SIG_BYTES \
    (XMSS_INDEX_BYTES + XMSS_N + \
     XMSS_D * (XMSS_WOTS_SIG_BYTES + XMSS_TREE_HEIGHT * XMSS_N))

#define XMSS_PK_BYTES \
    (2 * XMSS_N)

/* Select the correct API entirely at compile time. */
#if XMSS_D == 1

#define XMSS_IS_MT 0

#else

#define XMSS_IS_MT 1

#endif

#endif /* XMSS_PARAMS_H */
