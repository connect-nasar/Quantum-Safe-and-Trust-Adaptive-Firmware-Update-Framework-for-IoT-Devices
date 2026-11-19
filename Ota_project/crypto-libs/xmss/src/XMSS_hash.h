#ifndef XMSS_HASH_H
#define XMSS_HASH_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void sha256(unsigned char *out, const unsigned char *in, size_t inlen);
void sha512(unsigned char *out, const unsigned char *in, size_t inlen);
void shake128(unsigned char *output, unsigned long long outlen,
              const unsigned char *input, unsigned long long inlen);
void shake256(unsigned char *output, unsigned long long outlen,
              const unsigned char *input, unsigned long long inlen);

void sha256_inc_init(void *state);
void sha256_inc_update(void *state, const unsigned char *in, size_t inlen);
void sha256_inc_finalize(unsigned char *out, void *state);

void sha512_inc_init(void *state);
void sha512_inc_update(void *state, const unsigned char *in, size_t inlen);
void sha512_inc_finalize(unsigned char *out, void *state);

int xmss_prf(unsigned char *out, const unsigned char in[32],
        const unsigned char *key);


int prf_keygen(unsigned char *out, const unsigned char *in,
               const unsigned char *key);
int xmss_thash_h(unsigned char *out, const unsigned char *in,
            const unsigned char *pub_seed, uint32_t addr[8]);
int xmss_thash_f(unsigned char *out, const unsigned char *in,
            const unsigned char *pub_seed, uint32_t addr[8]);
int xmss_hash_message(unsigned char *out,
                 const unsigned char *R, const unsigned char *root,
                 unsigned long long idx,
                 unsigned char *m_with_prefix, unsigned long long mlen);

#ifdef __cplusplus
}
#endif

#endif
