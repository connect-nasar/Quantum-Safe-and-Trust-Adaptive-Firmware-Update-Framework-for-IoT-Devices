#ifndef XMSS_CONFIG_H
#define XMSS_CONFIG_H

/* Hash identifiers used by XMSS_hash.c. */
#define XMSS_HASH_SHA2       0
#define XMSS_HASH_SHAKE128   1
#define XMSS_HASH_SHAKE256   2

/*
 * Single Kyber-style compile-time selector.
 *
 * Examples:
 *     make XMSS_MODE=1
 *     make XMSS_MODE=12
 */
#ifndef XMSS_MODE
#define XMSS_MODE 1
#endif

/*
 * Standard-profile scope used here:
 *   - WOTS+ w is fixed to 16 for every mode.
 *   - BDS k is fixed to 2 for now.
 *
 * Mode layout:
 *   1-5   : XMSS,   tree/full height 10, D=1
 *   6-10  : XMSS,   tree/full height 20, D=1
 *   11-15 : XMSSMT, tree height 10, full height 20, D=2
 *   16-20 : XMSSMT, tree height 20, full height 40, D=2
 *
 * Within each group:
 *   1st: SHA-256       (n=32)
 *   2nd: SHA-512       (n=64)
 *   3rd: SHAKE128-256  (n=32)
 *   4th: SHAKE256-256  (n=32)
 *   5th: SHAKE256-512  (n=64)
 */

#if XMSS_MODE == 1

#define XMSS_CFG_NAME            "XMSS-H10-SHA-256"
#define XMSS_CFG_STRUCTURE_NAME  "XMSS-H10"
#define XMSS_CFG_HASH_NAME       "SHA-256"
#define XMSS_CFG_FUNC            XMSS_HASH_SHA2
#define XMSS_CFG_N               32
#define XMSS_CFG_PADDING         32
#define XMSS_CFG_TREE_HEIGHT     10
#define XMSS_CFG_HEIGHT          10
#define XMSS_CFG_D               1

#elif XMSS_MODE == 2

#define XMSS_CFG_NAME            "XMSS-H10-SHA-512"
#define XMSS_CFG_STRUCTURE_NAME  "XMSS-H10"
#define XMSS_CFG_HASH_NAME       "SHA-512"
#define XMSS_CFG_FUNC            XMSS_HASH_SHA2
#define XMSS_CFG_N               64
#define XMSS_CFG_PADDING         64
#define XMSS_CFG_TREE_HEIGHT     10
#define XMSS_CFG_HEIGHT          10
#define XMSS_CFG_D               1

#elif XMSS_MODE == 3

#define XMSS_CFG_NAME            "XMSS-H10-SHAKE128-256"
#define XMSS_CFG_STRUCTURE_NAME  "XMSS-H10"
#define XMSS_CFG_HASH_NAME       "SHAKE128-256"
#define XMSS_CFG_FUNC            XMSS_HASH_SHAKE128
#define XMSS_CFG_N               32
#define XMSS_CFG_PADDING         32
#define XMSS_CFG_TREE_HEIGHT     10
#define XMSS_CFG_HEIGHT          10
#define XMSS_CFG_D               1

#elif XMSS_MODE == 4

#define XMSS_CFG_NAME            "XMSS-H10-SHAKE256-256"
#define XMSS_CFG_STRUCTURE_NAME  "XMSS-H10"
#define XMSS_CFG_HASH_NAME       "SHAKE256-256"
#define XMSS_CFG_FUNC            XMSS_HASH_SHAKE256
#define XMSS_CFG_N               32
#define XMSS_CFG_PADDING         32
#define XMSS_CFG_TREE_HEIGHT     10
#define XMSS_CFG_HEIGHT          10
#define XMSS_CFG_D               1

#elif XMSS_MODE == 5

#define XMSS_CFG_NAME            "XMSS-H10-SHAKE256-512"
#define XMSS_CFG_STRUCTURE_NAME  "XMSS-H10"
#define XMSS_CFG_HASH_NAME       "SHAKE256-512"
#define XMSS_CFG_FUNC            XMSS_HASH_SHAKE256
#define XMSS_CFG_N               64
#define XMSS_CFG_PADDING         64
#define XMSS_CFG_TREE_HEIGHT     10
#define XMSS_CFG_HEIGHT          10
#define XMSS_CFG_D               1

#elif XMSS_MODE == 6

#define XMSS_CFG_NAME            "XMSS-H20-SHA-256"
#define XMSS_CFG_STRUCTURE_NAME  "XMSS-H20"
#define XMSS_CFG_HASH_NAME       "SHA-256"
#define XMSS_CFG_FUNC            XMSS_HASH_SHA2
#define XMSS_CFG_N               32
#define XMSS_CFG_PADDING         32
#define XMSS_CFG_TREE_HEIGHT     20
#define XMSS_CFG_HEIGHT          20
#define XMSS_CFG_D               1

#elif XMSS_MODE == 7

#define XMSS_CFG_NAME            "XMSS-H20-SHA-512"
#define XMSS_CFG_STRUCTURE_NAME  "XMSS-H20"
#define XMSS_CFG_HASH_NAME       "SHA-512"
#define XMSS_CFG_FUNC            XMSS_HASH_SHA2
#define XMSS_CFG_N               64
#define XMSS_CFG_PADDING         64
#define XMSS_CFG_TREE_HEIGHT     20
#define XMSS_CFG_HEIGHT          20
#define XMSS_CFG_D               1

#elif XMSS_MODE == 8

#define XMSS_CFG_NAME            "XMSS-H20-SHAKE128-256"
#define XMSS_CFG_STRUCTURE_NAME  "XMSS-H20"
#define XMSS_CFG_HASH_NAME       "SHAKE128-256"
#define XMSS_CFG_FUNC            XMSS_HASH_SHAKE128
#define XMSS_CFG_N               32
#define XMSS_CFG_PADDING         32
#define XMSS_CFG_TREE_HEIGHT     20
#define XMSS_CFG_HEIGHT          20
#define XMSS_CFG_D               1

#elif XMSS_MODE == 9

#define XMSS_CFG_NAME            "XMSS-H20-SHAKE256-256"
#define XMSS_CFG_STRUCTURE_NAME  "XMSS-H20"
#define XMSS_CFG_HASH_NAME       "SHAKE256-256"
#define XMSS_CFG_FUNC            XMSS_HASH_SHAKE256
#define XMSS_CFG_N               32
#define XMSS_CFG_PADDING         32
#define XMSS_CFG_TREE_HEIGHT     20
#define XMSS_CFG_HEIGHT          20
#define XMSS_CFG_D               1

#elif XMSS_MODE == 10

#define XMSS_CFG_NAME            "XMSS-H20-SHAKE256-512"
#define XMSS_CFG_STRUCTURE_NAME  "XMSS-H20"
#define XMSS_CFG_HASH_NAME       "SHAKE256-512"
#define XMSS_CFG_FUNC            XMSS_HASH_SHAKE256
#define XMSS_CFG_N               64
#define XMSS_CFG_PADDING         64
#define XMSS_CFG_TREE_HEIGHT     20
#define XMSS_CFG_HEIGHT          20
#define XMSS_CFG_D               1

#elif XMSS_MODE == 11

#define XMSS_CFG_NAME            "XMSSMT-H20-D2-SHA-256"
#define XMSS_CFG_STRUCTURE_NAME  "XMSSMT-H20-D2"
#define XMSS_CFG_HASH_NAME       "SHA-256"
#define XMSS_CFG_FUNC            XMSS_HASH_SHA2
#define XMSS_CFG_N               32
#define XMSS_CFG_PADDING         32
#define XMSS_CFG_TREE_HEIGHT     10
#define XMSS_CFG_HEIGHT          20
#define XMSS_CFG_D               2

#elif XMSS_MODE == 12

#define XMSS_CFG_NAME            "XMSSMT-H20-D2-SHA-512"
#define XMSS_CFG_STRUCTURE_NAME  "XMSSMT-H20-D2"
#define XMSS_CFG_HASH_NAME       "SHA-512"
#define XMSS_CFG_FUNC            XMSS_HASH_SHA2
#define XMSS_CFG_N               64
#define XMSS_CFG_PADDING         64
#define XMSS_CFG_TREE_HEIGHT     10
#define XMSS_CFG_HEIGHT          20
#define XMSS_CFG_D               2

#elif XMSS_MODE == 13

#define XMSS_CFG_NAME            "XMSSMT-H20-D2-SHAKE128-256"
#define XMSS_CFG_STRUCTURE_NAME  "XMSSMT-H20-D2"
#define XMSS_CFG_HASH_NAME       "SHAKE128-256"
#define XMSS_CFG_FUNC            XMSS_HASH_SHAKE128
#define XMSS_CFG_N               32
#define XMSS_CFG_PADDING         32
#define XMSS_CFG_TREE_HEIGHT     10
#define XMSS_CFG_HEIGHT          20
#define XMSS_CFG_D               2

#elif XMSS_MODE == 14

#define XMSS_CFG_NAME            "XMSSMT-H20-D2-SHAKE256-256"
#define XMSS_CFG_STRUCTURE_NAME  "XMSSMT-H20-D2"
#define XMSS_CFG_HASH_NAME       "SHAKE256-256"
#define XMSS_CFG_FUNC            XMSS_HASH_SHAKE256
#define XMSS_CFG_N               32
#define XMSS_CFG_PADDING         32
#define XMSS_CFG_TREE_HEIGHT     10
#define XMSS_CFG_HEIGHT          20
#define XMSS_CFG_D               2

#elif XMSS_MODE == 15

#define XMSS_CFG_NAME            "XMSSMT-H20-D2-SHAKE256-512"
#define XMSS_CFG_STRUCTURE_NAME  "XMSSMT-H20-D2"
#define XMSS_CFG_HASH_NAME       "SHAKE256-512"
#define XMSS_CFG_FUNC            XMSS_HASH_SHAKE256
#define XMSS_CFG_N               64
#define XMSS_CFG_PADDING         64
#define XMSS_CFG_TREE_HEIGHT     10
#define XMSS_CFG_HEIGHT          20
#define XMSS_CFG_D               2

#elif XMSS_MODE == 16

#define XMSS_CFG_NAME            "XMSSMT-H40-D2-SHA-256"
#define XMSS_CFG_STRUCTURE_NAME  "XMSSMT-H40-D2"
#define XMSS_CFG_HASH_NAME       "SHA-256"
#define XMSS_CFG_FUNC            XMSS_HASH_SHA2
#define XMSS_CFG_N               32
#define XMSS_CFG_PADDING         32
#define XMSS_CFG_TREE_HEIGHT     20
#define XMSS_CFG_HEIGHT          40
#define XMSS_CFG_D               2

#elif XMSS_MODE == 17

#define XMSS_CFG_NAME            "XMSSMT-H40-D2-SHA-512"
#define XMSS_CFG_STRUCTURE_NAME  "XMSSMT-H40-D2"
#define XMSS_CFG_HASH_NAME       "SHA-512"
#define XMSS_CFG_FUNC            XMSS_HASH_SHA2
#define XMSS_CFG_N               64
#define XMSS_CFG_PADDING         64
#define XMSS_CFG_TREE_HEIGHT     20
#define XMSS_CFG_HEIGHT          40
#define XMSS_CFG_D               2

#elif XMSS_MODE == 18

#define XMSS_CFG_NAME            "XMSSMT-H40-D2-SHAKE128-256"
#define XMSS_CFG_STRUCTURE_NAME  "XMSSMT-H40-D2"
#define XMSS_CFG_HASH_NAME       "SHAKE128-256"
#define XMSS_CFG_FUNC            XMSS_HASH_SHAKE128
#define XMSS_CFG_N               32
#define XMSS_CFG_PADDING         32
#define XMSS_CFG_TREE_HEIGHT     20
#define XMSS_CFG_HEIGHT          40
#define XMSS_CFG_D               2

#elif XMSS_MODE == 19

#define XMSS_CFG_NAME            "XMSSMT-H40-D2-SHAKE256-256"
#define XMSS_CFG_STRUCTURE_NAME  "XMSSMT-H40-D2"
#define XMSS_CFG_HASH_NAME       "SHAKE256-256"
#define XMSS_CFG_FUNC            XMSS_HASH_SHAKE256
#define XMSS_CFG_N               32
#define XMSS_CFG_PADDING         32
#define XMSS_CFG_TREE_HEIGHT     20
#define XMSS_CFG_HEIGHT          40
#define XMSS_CFG_D               2

#elif XMSS_MODE == 20

#define XMSS_CFG_NAME            "XMSSMT-H40-D2-SHAKE256-512"
#define XMSS_CFG_STRUCTURE_NAME  "XMSSMT-H40-D2"
#define XMSS_CFG_HASH_NAME       "SHAKE256-512"
#define XMSS_CFG_FUNC            XMSS_HASH_SHAKE256
#define XMSS_CFG_N               64
#define XMSS_CFG_PADDING         64
#define XMSS_CFG_TREE_HEIGHT     20
#define XMSS_CFG_HEIGHT          40
#define XMSS_CFG_D               2

#else
#error "XMSS_MODE must be between 1 and 20"
#endif

/*
 * Fixed parameters for the current standards-aligned scope.
 * They are not independently user-selectable.
 */
#define XMSS_CFG_WOTS_W 16
#define XMSS_CFG_BDS_K  2

#endif /* XMSS_CONFIG_H */
