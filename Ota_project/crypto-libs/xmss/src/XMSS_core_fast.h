#ifndef XMSS_CORE_FAST_H
#define XMSS_CORE_FAST_H

#include "XMSS_params.h"

unsigned long long xmss_xmssmt_core_sk_bytes(void);
int xmss_fast_keypair(unsigned char *pk, unsigned char *sk);
int xmss_fast_sign(unsigned char *sk,
                   unsigned char *sm, unsigned long long *smlen,
                   const unsigned char *m, unsigned long long mlen);
int xmssmt_fast_keypair(unsigned char *pk, unsigned char *sk);
int xmssmt_fast_sign(unsigned char *sk,
                     unsigned char *sm, unsigned long long *smlen,
                     const unsigned char *m, unsigned long long mlen);

#endif
