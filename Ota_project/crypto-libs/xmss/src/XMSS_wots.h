#ifndef XMSS_WOTS_H
#define XMSS_WOTS_H

#include <stdint.h>
#include "XMSS_params.h"

void xmss_wots_pkgen(unsigned char *pk, const unsigned char *seed,
                const unsigned char *pub_seed, uint32_t addr[8]);
void xmss_wots_sign(unsigned char *sig, const unsigned char *msg,
               const unsigned char *seed, const unsigned char *pub_seed,
               uint32_t addr[8]);
void wots_pk_from_sig(unsigned char *pk,
                      const unsigned char *sig, const unsigned char *msg,
                      const unsigned char *pub_seed, uint32_t addr[8]);

#endif
