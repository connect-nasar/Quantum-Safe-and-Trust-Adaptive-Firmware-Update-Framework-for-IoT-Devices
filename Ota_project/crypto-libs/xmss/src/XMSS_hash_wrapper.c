// ====================================================================
// FINAL, CORRECTED hash_wrapper.c
// This file provides ONLY the self-contained SHA-256 and SHA-512 functions.
// ====================================================================

#include <stddef.h>
#include "XMSS_hash.h"
#include "XMSS_sha256.h"  // Provides both SHA-256 and SHA-512 implementations

/**
 * @brief One-shot SHA-256 hash function.
 */
void sha256(unsigned char *out, const unsigned char *in, size_t inlen) {
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, in, inlen);
    sha256_final(&ctx, out);
}

/**
 * @brief Incremental SHA-256 API.
 */
void sha256_inc_init(void *statev) {
    sha256_init((SHA256_CTX*)statev);
}

void sha256_inc_update(void *statev, const unsigned char *in, size_t inlen) {
    sha256_update((SHA256_CTX*)statev, in, inlen);
}

void sha256_inc_finalize(unsigned char *out, void *statev) {
    sha256_final((SHA256_CTX*)statev, out);
}

/* SHA-512 one-shot is implemented in sha256.c; we just need to declare it.
 * The incremental stubs are also provided there (empty). */