#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "fips202.h"

#define NROUNDS 24
#define ROL(a, offset) ((a << offset) ^ (a >> (64-offset)))

const uint64_t KeccakF_RoundConstants[NROUNDS] = {
  (uint64_t)0x0000000000000001ULL,
  (uint64_t)0x0000000000008082ULL,
  (uint64_t)0x800000000000808aULL,
  (uint64_t)0x8000000080008000ULL,
  (uint64_t)0x000000000000808bULL,
  (uint64_t)0x0000000080000001ULL,
  (uint64_t)0x8000000080008081ULL,
  (uint64_t)0x8000000000008009ULL,
  (uint64_t)0x000000000000008aULL,
  (uint64_t)0x0000000000000088ULL,
  (uint64_t)0x0000000080008009ULL,
  (uint64_t)0x000000008000000aULL,
  (uint64_t)0x000000008000808bULL,
  (uint64_t)0x800000000000008bULL,
  (uint64_t)0x8000000000008089ULL,
  (uint64_t)0x8000000000008003ULL,
  (uint64_t)0x8000000000008002ULL,
  (uint64_t)0x8000000000000080ULL,
  (uint64_t)0x000000000000800aULL,
  (uint64_t)0x800000008000000aULL,
  (uint64_t)0x8000000080008081ULL,
  (uint64_t)0x8000000000008080ULL,
  (uint64_t)0x0000000080000001ULL,
  (uint64_t)0x8000000080008008ULL
};

void KeccakF1600_StatePermute(uint64_t state[25])
{
    int round, y;
    uint64_t b[5];
    uint64_t t, t12, t34;
    uint64_t nxt[25];

    for(round = 0; round < NROUNDS; round++) {

        b[0] = state[0] ^ state[5] ^ state[10] ^ state[15] ^ state[20];
        b[1] = state[1] ^ state[6] ^ state[11] ^ state[16] ^ state[21];
        b[2] = state[2] ^ state[7] ^ state[12] ^ state[17] ^ state[22];
        b[3] = state[3] ^ state[8] ^ state[13] ^ state[18] ^ state[23];
        b[4] = state[4] ^ state[9] ^ state[14] ^ state[19] ^ state[24];

        t = b[4] ^ ROL(b[1], 1); state[0]^=t; state[5]^=t; state[10]^=t; state[15]^=t; state[20]^=t;
        t = b[0] ^ ROL(b[2], 1); state[1]^=t; state[6]^=t; state[11]^=t; state[16]^=t; state[21]^=t;
        t = b[1] ^ ROL(b[3], 1); state[2]^=t; state[7]^=t; state[12]^=t; state[17]^=t; state[22]^=t;
        t = b[2] ^ ROL(b[4], 1); state[3]^=t; state[8]^=t; state[13]^=t; state[18]^=t; state[23]^=t;
        t = b[3] ^ ROL(b[0], 1); state[4]^=t; state[9]^=t; state[14]^=t; state[19]^=t; state[24]^=t;

        nxt[ 0] = state[ 0];
        nxt[ 1] = ROL(state[ 6], 44);
        nxt[ 2] = ROL(state[12], 43);
        nxt[ 3] = ROL(state[18], 21);
        nxt[ 4] = ROL(state[24], 14);

        nxt[ 5] = ROL(state[ 3], 28);
        nxt[ 6] = ROL(state[ 9], 20);
        nxt[ 7] = ROL(state[10],  3);
        nxt[ 8] = ROL(state[16], 45);
        nxt[ 9] = ROL(state[22], 61);

        nxt[10] = ROL(state[ 1],  1);
        nxt[11] = ROL(state[ 7],  6);
        nxt[12] = ROL(state[13], 25);
        nxt[13] = ROL(state[19],  8);
        nxt[14] = ROL(state[20], 18);

        nxt[15] = ROL(state[ 4], 27);
        nxt[16] = ROL(state[ 5], 36);
        nxt[17] = ROL(state[11], 10);
        nxt[18] = ROL(state[17], 15);
        nxt[19] = ROL(state[23], 56);

        nxt[20] = ROL(state[ 2], 62);
        nxt[21] = ROL(state[ 8], 55);
        nxt[22] = ROL(state[14], 39);
        nxt[23] = ROL(state[15], 41);
        nxt[24] = ROL(state[21],  2);

        for (y = 0; y < 5; y++) {
            b[0] = nxt[y * 5 + 0];
            b[1] = nxt[y * 5 + 1];
            b[2] = nxt[y * 5 + 2];
            b[3] = nxt[y * 5 + 3];
            b[4] = nxt[y * 5 + 4];

            t12 = b[1] ^ b[2];
            t34 = b[3] ^ b[4];

            state[y * 5 + 0] = b[0] ^ (b[2] & t12);
            state[y * 5 + 1] = t12  ^ (b[2] | b[3]);
            state[y * 5 + 2] = b[2] ^ (b[4] & t34);
            state[y * 5 + 3] = t34  ^ (b[4] | b[0]);
            state[y * 5 + 4] = b[4] ^ (b[1] & (b[0] ^ b[1]));
        }

        state[0] ^= KeccakF_RoundConstants[round];
    }
}

static void keccak_init(uint64_t * restrict s)
{
    memset(s, 0, 25 * sizeof(uint64_t));
}

static unsigned int keccak_absorb(uint64_t * restrict s,
                                      unsigned int pos,
                                      unsigned int r,
                                      const uint8_t * restrict in,
                                      size_t inlen)
{
    uint8_t *state_bytes = (uint8_t *)s;

    while(pos + inlen >= r) {
        unsigned int chunk = r - pos;
        for (unsigned int i = 0; i < chunk; i++) {
            state_bytes[pos + i] ^= in[i];
        }
        in += chunk;
        inlen -= chunk;
        KeccakF1600_StatePermute(s);
        pos = 0;
    }

    for (unsigned int i = 0; i < inlen; i++) {
        state_bytes[pos + i] ^= in[i];
    }

    return pos + inlen;
}

static void keccak_finalize(uint64_t * restrict s, unsigned int pos, unsigned int r, uint8_t p)
{
    uint8_t *state_bytes = (uint8_t *)s;
    state_bytes[pos] ^= p;
    state_bytes[r - 1] ^= 0x80;
}

static unsigned int keccak_squeeze(uint8_t * restrict out,
                                       size_t outlen,
                                       uint64_t s[25],
                                       unsigned int pos,
                                       unsigned int r)
{
    uint8_t *state_bytes = (uint8_t *)s;

    while(outlen > 0) {
        if(pos == r) {
            KeccakF1600_StatePermute(s);
            pos = 0;
        }

        unsigned int chunk = r - pos;
        if (chunk > outlen) {
            chunk = outlen;
        }

        memcpy(out, state_bytes + pos, chunk);

        out += chunk;
        outlen -= chunk;
        pos += chunk;
    }

    return pos;
}

static void keccak_absorb_once(uint64_t s[25],
                                   unsigned int r,
                                   const uint8_t * restrict in,
                                   size_t inlen,
                                   uint8_t p)
{
    memset(s, 0, 25 * sizeof(uint64_t));
    uint8_t *state_bytes = (uint8_t *)s;

    while(inlen >= r) {
        for (unsigned int i = 0; i < r; i++) {
            state_bytes[i] ^= in[i];
        }
        in += r;
        inlen -= r;
        KeccakF1600_StatePermute(s);
    }

    for (unsigned int i = 0; i < inlen; i++) {
        state_bytes[i] ^= in[i];
    }

    state_bytes[inlen] ^= p;
    state_bytes[r - 1] ^= 0x80;
}

void shake128_init(keccak_state * restrict state)
{
    keccak_init(state->s);
    state->pos = 0;
}

void shake128_absorb(keccak_state * restrict state, const uint8_t * restrict in, size_t inlen)
{
    state->pos = keccak_absorb(state->s, state->pos, SHAKE128_RATE, in, inlen);
}

void shake128_finalize(keccak_state * restrict state)
{
    keccak_finalize(state->s, state->pos, SHAKE128_RATE, 0x1F);
    state->pos = SHAKE128_RATE;
}

void shake128_squeeze(uint8_t *out, size_t outlen, keccak_state *state)
{
    state->pos = keccak_squeeze(out, outlen, state->s, state->pos, SHAKE128_RATE);
}

void shake128_absorb_once(keccak_state *state, const uint8_t *in, size_t inlen)
{
    keccak_absorb_once(state->s, SHAKE128_RATE, in, inlen, 0x1F);
    state->pos = SHAKE128_RATE;
}

void shake128_squeezeblocks(uint8_t * restrict out,
                                size_t nblocks,
                                keccak_state * restrict state)
{
    while(nblocks--) {
        KeccakF1600_StatePermute(state->s);
        
        memcpy(out, state->s, SHAKE128_RATE);
        out += SHAKE128_RATE;
    }
}

void shake256_init(keccak_state *state)
{
    keccak_init(state->s);
    state->pos = 0;
}

void shake256_absorb(keccak_state *state, const uint8_t *input_bytes, size_t input_length)
{
    state->pos = keccak_absorb(state->s, state->pos, SHAKE256_RATE, input_bytes, input_length);
}

void shake256_finalize(keccak_state *state)
{
    keccak_finalize(state->s, state->pos, SHAKE256_RATE, 0x1F);
    state->pos = SHAKE256_RATE;
}

void shake256_squeeze(uint8_t * restrict out_bytes, size_t out_len, keccak_state * restrict state)
{
    state->pos = keccak_squeeze(out_bytes, out_len, state->s, state->pos, SHAKE256_RATE);
}

void shake256_absorb_once(keccak_state * restrict state, const uint8_t * restrict in_bytes, size_t in_len)
{
    keccak_absorb_once(state->s, SHAKE256_RATE, in_bytes, in_len, 0x1F);
    state->pos = SHAKE256_RATE;
}

void shake256_squeezeblocks(uint8_t * restrict out,
                                size_t nblocks,
                                keccak_state * restrict state)
{
    while(nblocks--) {
        KeccakF1600_StatePermute(state->s);
        
        memcpy(out, state->s, SHAKE256_RATE);
        out += SHAKE256_RATE;
    }
}

void shake128(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen)
{
  size_t nblocks;
  keccak_state state;

  shake128_absorb_once(&state, in, inlen);
  nblocks = outlen/SHAKE128_RATE;
  shake128_squeezeblocks(out, nblocks, &state);
  outlen -= nblocks*SHAKE128_RATE;
  out += nblocks*SHAKE128_RATE;
  shake128_squeeze(out, outlen, &state);
}

void shake256(uint8_t * restrict out,
              size_t outlen,
              const uint8_t * restrict in,
              size_t inlen)
{
  keccak_state state;

  shake256_absorb_once(&state, in, inlen);

  while(outlen >= SHAKE256_RATE) {
    shake256_squeezeblocks(out, 1, &state);
    out += SHAKE256_RATE;
    outlen -= SHAKE256_RATE;
  }

  if (outlen > 0) {
    shake256_squeeze(out, outlen, &state);
  }
}

void sha3_256(uint8_t h[32], const uint8_t *in, size_t inlen)
{
  uint64_t s[25];

  keccak_absorb_once(s, SHA3_256_RATE, in, inlen, 0x06);
  KeccakF1600_StatePermute(s);

  memcpy(h, s, 32);
}

void sha3_512(uint8_t h[64], const uint8_t *in, size_t inlen)
{
  uint64_t s[25];

  keccak_absorb_once(s, SHA3_512_RATE, in, inlen, 0x06);
  KeccakF1600_StatePermute(s);

  memcpy(h, s, 64);
}
