#ifndef XMSS_COMMONS_H
#define XMSS_COMMONS_H

#include <stdint.h>
#include "XMSS_params.h"

void xmss_gen_leaf_wots(unsigned char *leaf,
                   const unsigned char *sk_seed, const unsigned char *pub_seed,
                   uint32_t ltree_addr[8], uint32_t ots_addr[8]);

int xmss_core_sign_open(unsigned char *m, unsigned long long *mlen,
                        const unsigned char *sm, unsigned long long smlen,
                        const unsigned char *pk);

int xmssmt_core_sign_open(unsigned char *m, unsigned long long *mlen,
                          const unsigned char *sm, unsigned long long smlen,
                          const unsigned char *pk);

#endif
