#include <stdint.h>
#include "XMSS_params.h"
#include "XMSS_core_fast.h"
#include "XMSS_commons.h"
#include "XMSS_xmss.h"

// static const uint32_t FIXED_OID = 0x00000001; /* it was removed */

int xmss_keypair(unsigned char *pk, unsigned char *sk)
{

#if XMSS_IS_MT
    return xmssmt_fast_keypair(pk, sk);
#else
    return xmss_fast_keypair(pk , sk);
#endif
}

int xmss_sign(unsigned char *restrict sk,
              unsigned char *restrict sm, unsigned long long *restrict smlen,
              const unsigned char *restrict m, unsigned long long mlen)
{
#if XMSS_IS_MT
    return xmssmt_fast_sign(sk, sm, smlen, m, mlen);
#else
    return xmss_fast_sign(sk , sm, smlen, m, mlen);
#endif
}

int xmss_sign_open(unsigned char *m, unsigned long long *mlen,
                   const unsigned char *sm, unsigned long long smlen,
                   const unsigned char *pk)
{
#if XMSS_IS_MT
    return xmssmt_core_sign_open(m, mlen, sm, smlen, pk);
#else
    return xmss_core_sign_open(m, mlen, sm, smlen, pk);
#endif
}

int xmssmt_keypair(unsigned char *pk, unsigned char *sk)
{
   
    return xmssmt_fast_keypair(pk, sk);
}

int xmssmt_sign(unsigned char *sk,
                unsigned char *sm, unsigned long long *smlen,
                const unsigned char *m, unsigned long long mlen)
{
    return xmssmt_fast_sign(sk , sm, smlen, m, mlen);
}

int xmssmt_sign_open(unsigned char *restrict m, unsigned long long *mlen,
                     const unsigned char *restrict sm, unsigned long long smlen,
                     const unsigned char *restrict pk)
{
    return xmssmt_core_sign_open(m, mlen, sm, smlen, pk);
}
