#ifndef MLK_ESP32_FIPS202_H
#define MLK_ESP32_FIPS202_H

#include <string.h>

#include <fips202.h>

#define mlk_shake128ctx keccak_state
#define mlk_shake128_init shake128_init
#define mlk_shake128_absorb_once shake128_absorb_once
#define mlk_shake128_squeezeblocks shake128_squeezeblocks
#define mlk_shake256 shake256
#define mlk_sha3_256 sha3_256
#define mlk_sha3_512 sha3_512

static inline void mlk_shake128_release(keccak_state *state)
{
	memset(state, 0, sizeof(*state));
}

#endif
