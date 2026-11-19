#include <stdint.h>
#include <string.h>
#include "XMSS_utils.h"
#include "XMSS_hash.h"
#include "XMSS_wots.h"
#include "XMSS_hash_address.h"
#include "XMSS_params.h"

static void expand_seed(unsigned char *outseeds, const unsigned char *restrict inseed,
                        const unsigned char *restrict pub_seed, uint32_t addr[restrict 8])
{
    uint32_t i;
    unsigned char buf[XMSS_N + 32];
    set_hash_addr(addr, 0);
    set_key_and_mask(addr, 0);
    memcpy(buf, pub_seed, XMSS_N);
    for (i = 0; i < XMSS_WOTS_LEN; i++) {
        set_chain_addr(addr, i);
        addr_to_bytes(buf + XMSS_N, addr);
        prf_keygen(outseeds + i * XMSS_N, buf, inseed);
    }
}

static inline void xmss_gen_chain(unsigned char *out, const unsigned char *in,
                      unsigned int start, unsigned int steps,
                      const unsigned char *restrict pub_seed, uint32_t addr[8])
{
    unsigned int i;
    unsigned int end;

    if (start >= XMSS_WOTS_W) {
        if (out != in) {
            memcpy(out, in, XMSS_N);
        }
        return;
    }

    if (steps > XMSS_WOTS_W - start) {
        steps = XMSS_WOTS_W - start;
    }

    end = start + steps;

    if (out != in) {
        memcpy(out, in, XMSS_N);
    }

    for (i = start; i < end; i++) {
        set_hash_addr(addr, i);
        xmss_thash_f(out, out, pub_seed, addr);
    }
}

static void base_w(int *output, const int out_len, const unsigned char *input)
{
    int in = 0;
    int out = 0;
    unsigned char total;
    int bits = 0;
    int consumed;
    for (consumed = 0; consumed < out_len; consumed++) {
        if (bits == 0) {
            total = input[in];
            in++;
            bits += 8;
        }
        bits -= XMSS_WOTS_LOG_W;
        output[out] = (total >> bits) & (XMSS_WOTS_W - 1);
        out++;
    }
}

static void wots_checksum(int *csum_base_w, const int *msg_base_w)
{
    int csum = 0;
    unsigned char csum_bytes[(XMSS_WOTS_LEN2 * XMSS_WOTS_LOG_W + 7) / 8];
    unsigned int i;
    for (i = 0; i < XMSS_WOTS_LEN1; i++) {
        csum += XMSS_WOTS_W - 1 - msg_base_w[i];
    }
    csum = csum << (8 - ((XMSS_WOTS_LEN2 * XMSS_WOTS_LOG_W) % 8));
    xmss_ull_to_bytes(csum_bytes, sizeof(csum_bytes), csum);
    base_w(csum_base_w, XMSS_WOTS_LEN2, csum_bytes);
}

static void chain_lengths(int *lengths, const unsigned char *msg)
{
    base_w(lengths, XMSS_WOTS_LEN1, msg);
    wots_checksum(lengths + XMSS_WOTS_LEN1, lengths);
}

void xmss_wots_pkgen(unsigned char *pk,
                         const unsigned char *seed,
                         const unsigned char *pub_seed,
                         uint32_t addr[8])
{
    uint32_t i;
    unsigned char *pk_element = pk;

    expand_seed(pk, seed, pub_seed, addr);

    for (i = 0; i < XMSS_WOTS_LEN; ++i) {
        set_chain_addr(addr, i);

        xmss_gen_chain(
            pk_element,
            pk_element,
            0,
            XMSS_WOTS_W - 1,
            pub_seed,
            addr
        );

        pk_element += XMSS_N;
    }
}

void xmss_wots_sign(unsigned char *restrict sig, const unsigned char *restrict msg,
               const unsigned char *restrict seed, const unsigned char *restrict pub_seed,
               uint32_t addr[restrict 8])
{
    int lengths[XMSS_WOTS_LEN];
    uint32_t i;
    chain_lengths(lengths, msg);
    expand_seed(sig, seed, pub_seed, addr);
    unsigned char *sig_ptr = sig;

    for (i = 0; i < XMSS_WOTS_LEN; i++) {
        set_chain_addr(addr, i);
        xmss_gen_chain(sig_ptr, sig_ptr, 0, lengths[i], pub_seed, addr);
        sig_ptr += XMSS_N;
    }
}

void wots_pk_from_sig(unsigned char *restrict pk,
                      const unsigned char *restrict sig, const unsigned char *restrict msg,
                      const unsigned char *restrict pub_seed, uint32_t addr[restrict 8])
{
    int lengths[XMSS_WOTS_LEN];
    uint32_t i;
    chain_lengths(lengths, msg);
    for (i = 0; i < XMSS_WOTS_LEN; i++) {
        set_chain_addr(addr, i);
        xmss_gen_chain(pk + i * XMSS_N, sig + i * XMSS_N,
                  lengths[i], XMSS_WOTS_W - 1 - lengths[i], pub_seed, addr);
    }
}
