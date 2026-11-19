#include <stdint.h>
#include <string.h>
#include "XMSS_hash.h"
#include "XMSS_hash_address.h"
#include "XMSS_utils.h"
#include "XMSS_params.h"
#include "fips202.h"

#define XMSS_HASH_PADDING_F 0
#define XMSS_HASH_PADDING_H 1
#define XMSS_HASH_PADDING_HASH 2
#define XMSS_HASH_PADDING_PRF 3
#define XMSS_HASH_PADDING_PRF_KEYGEN 4

void addr_to_bytes(unsigned char *bytes, const uint32_t addr[8])
{
    int i;
    for (i = 0; i < 8; i++) {
        xmss_ull_to_bytes(bytes + i*4, 4, addr[i]);
    }
}



static inline int xmss_core_hash(unsigned char *out,
                              const unsigned char *restrict in,
                              unsigned long long inlen)
{

#if (XMSS_N == 32 && XMSS_CFG_FUNC == XMSS_SHA2)
    sha256(out, in, inlen);

#elif (XMSS_N == 24 && XMSS_CFG_FUNC == XMSS_SHA2)
    unsigned char buf[32];
    sha256(buf, in, inlen);
    memcpy(out, buf, 24);

#elif (XMSS_N == 64 && XMSS_CFG_FUNC == XMSS_SHA2)
    sha512(out, in, inlen);

#elif (XMSS_N == 32 && XMSS_CFG_FUNC == XMSS_SHAKE128)
    shake128(out, 32, in, inlen);

#elif (XMSS_N == 24 && XMSS_CFG_FUNC == XMSS_SHAKE256)
    shake256(out, 24, in, inlen);

#elif (XMSS_N == 32 && XMSS_CFG_FUNC == XMSS_SHAKE256)
    shake256(out, 32, in, inlen);

#elif (XMSS_N == 64 && XMSS_CFG_FUNC == XMSS_SHAKE256)
    shake256(out, 64, in, inlen);

#else
    #warning "Unsupported XMSS_N and XMSS_CFG_FUNC combination in core_hash"
    return -1;

#endif

    return 0;
}

int xmss_prf(unsigned char *out, const unsigned char in[restrict 32],
        const unsigned char *restrict key)
{
    unsigned char buf[XMSS_PADDING_LEN + XMSS_N + 32U];
    unsigned char *const key_dst = buf + XMSS_PADDING_LEN;
    unsigned char *const input_dst = key_dst + XMSS_N;
    xmss_ull_to_bytes(buf, XMSS_PADDING_LEN, XMSS_HASH_PADDING_PRF);
    memcpy(key_dst, key, XMSS_N);
    memcpy(input_dst, in, 32U);
    return xmss_core_hash(out, buf, sizeof(buf));
}

int prf_keygen(unsigned char *out, const unsigned char *in,
               const unsigned char *key)
{
    unsigned char buf[XMSS_PADDING_LEN + 2*XMSS_N + 32];
    xmss_ull_to_bytes(buf, XMSS_PADDING_LEN, XMSS_HASH_PADDING_PRF_KEYGEN);
    memcpy(buf + XMSS_PADDING_LEN, key, XMSS_N);
    memcpy(buf + XMSS_PADDING_LEN + XMSS_N, in, XMSS_N + 32);
    return xmss_core_hash(out, buf, XMSS_PADDING_LEN + 2*XMSS_N + 32);
}

int xmss_hash_message(unsigned char *restrict out,
                 const unsigned char *restrict R, const unsigned char *restrict root,
                 unsigned long long idx,
                 unsigned char *m_with_prefix, unsigned long long mlen)
{
    xmss_ull_to_bytes(m_with_prefix, XMSS_PADDING_LEN, XMSS_HASH_PADDING_HASH);
    memcpy(m_with_prefix + XMSS_PADDING_LEN, R, XMSS_N);
    memcpy(m_with_prefix + XMSS_PADDING_LEN + XMSS_N, root, XMSS_N);
    xmss_ull_to_bytes(m_with_prefix + XMSS_PADDING_LEN + 2*XMSS_N, XMSS_N, idx);
    return xmss_core_hash(out, m_with_prefix, mlen + XMSS_PADDING_LEN + 3*XMSS_N);
}

int xmss_thash_h(unsigned char *out,
                     const unsigned char *in,
                     const unsigned char *pub_seed,
                     uint32_t addr[8])
{
    unsigned char buf[XMSS_PADDING_LEN + 3U * XMSS_N];
    unsigned char addr_as_bytes[32];
    unsigned int i;

    xmss_ull_to_bytes(buf, XMSS_PADDING_LEN, XMSS_HASH_PADDING_H);

    /* Generate the key directly inside buf. */
    set_key_and_mask(addr, 0);
    addr_to_bytes(addr_as_bytes, addr);
    xmss_prf(buf + XMSS_PADDING_LEN, addr_as_bytes, pub_seed);

    /* Generate the left mask directly inside buf. */
    set_key_and_mask(addr, 1);
    addr_to_bytes(addr_as_bytes, addr);
    xmss_prf(buf + XMSS_PADDING_LEN + XMSS_N,
        addr_as_bytes,
        pub_seed);

    /* Generate the right mask directly inside buf. */
    set_key_and_mask(addr, 2);
    addr_to_bytes(addr_as_bytes, addr);
    xmss_prf(buf + XMSS_PADDING_LEN + 2U * XMSS_N,
        addr_as_bytes,
        pub_seed);

    /*
     * The local hash buffer and external input cannot overlap.
     * Keep restrict limited to this XOR operation.
     */
    {
        unsigned char *restrict masked_nodes =
            buf + XMSS_PADDING_LEN + XMSS_N;

        const unsigned char *restrict input_nodes = in;

        for (i = 0; i < 2U * XMSS_N; ++i) {
            masked_nodes[i] ^= input_nodes[i];
        }
    }

    return xmss_core_hash(out,
                     buf,
                     XMSS_PADDING_LEN + 3U * XMSS_N);
}

int xmss_thash_f(unsigned char *out,
                     const unsigned char *in,
                     const unsigned char *restrict pub_seed,
                     uint32_t addr[restrict 8])
{
    unsigned char buf[XMSS_PADDING_LEN + 2 * XMSS_N];
    unsigned char addr_as_bytes[32];
    unsigned char *const key = buf + XMSS_PADDING_LEN;
    unsigned char *const masked = key + XMSS_N;
    unsigned int i;

    xmss_ull_to_bytes(buf, XMSS_PADDING_LEN, XMSS_HASH_PADDING_F);

    set_key_and_mask(addr, 0);
    addr_to_bytes(addr_as_bytes, addr);
    xmss_prf(key, addr_as_bytes, pub_seed);

    set_key_and_mask(addr, 1);
    xmss_ull_to_bytes(addr_as_bytes + 28, 4, 1);
    xmss_prf(masked, addr_as_bytes, pub_seed);

    for (i = 0; i < XMSS_N; i++) {
        masked[i] ^= in[i];
    }

    return xmss_core_hash(out, buf, sizeof(buf));
}
