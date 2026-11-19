#ifndef XMSS_H
#define XMSS_H

#include <stdint.h>

int xmss_keypair(unsigned char *pk, unsigned char *sk);
int xmss_sign(unsigned char *sk,
              unsigned char *sm, unsigned long long *smlen,
              const unsigned char *m, unsigned long long mlen);
int xmss_sign_open(unsigned char *m, unsigned long long *mlen,
                   const unsigned char *sm, unsigned long long smlen,
                   const unsigned char *pk);

int xmssmt_keypair(unsigned char *pk, unsigned char *sk);
int xmssmt_sign(unsigned char *sk,
                unsigned char *sm, unsigned long long *smlen,
                const unsigned char *m, unsigned long long mlen);
int xmssmt_sign_open(unsigned char *m, unsigned long long *mlen,
                     const unsigned char *sm, unsigned long long smlen,
                     const unsigned char *pk);

#endif
