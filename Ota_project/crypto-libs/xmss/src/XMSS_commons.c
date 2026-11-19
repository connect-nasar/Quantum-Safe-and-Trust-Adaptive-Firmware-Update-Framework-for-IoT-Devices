#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "XMSS_hash.h"
#include "XMSS_hash_address.h"
#include "XMSS_params.h"
#include "XMSS_wots.h"
#include "XMSS_utils.h"
#include "XMSS_commons.h"

static void xmss_l_tree(
    unsigned char *restrict leaf,
    unsigned char *restrict wots_pk,
    const unsigned char *restrict pub_seed,
    uint32_t addr[restrict 8])
{
    unsigned int l = XMSS_WOTS_LEN;
    uint32_t height = 0;

    while (l > 1U) {
        const unsigned int parent_nodes = l >> 1;
        const unsigned int odd_node = l & 1U;
        unsigned int i;

        set_tree_height(addr, height);

        for (i = 0; i < parent_nodes; ++i) {
            set_tree_index(addr, i);

            xmss_thash_h(
                wots_pk + i * XMSS_N,
                wots_pk + (2U * i) * XMSS_N,
                pub_seed,
                addr);
        }

        /* Carry the remaining node to the next level. */
        if (odd_node != 0U) {
            memcpy(wots_pk + parent_nodes * XMSS_N,
                   wots_pk + (l - 1U) * XMSS_N,
                   XMSS_N);
        }

        l = parent_nodes + odd_node;
        ++height;
    }

    memcpy(leaf, wots_pk, XMSS_N);
}

static void compute_root(unsigned char *root,
                         const unsigned char *leaf, unsigned long leafidx,
                         const unsigned char *auth_path,
                         const unsigned char *pub_seed, uint32_t addr[8])
{
    uint32_t i;
    unsigned char buffer[2 * XMSS_N];

    if (leafidx & 1) {
        memcpy(buffer + XMSS_N, leaf, XMSS_N);
        memcpy(buffer, auth_path, XMSS_N);
    }
    else {
        memcpy(buffer, leaf, XMSS_N);
        memcpy(buffer + XMSS_N, auth_path, XMSS_N);
    }
    auth_path += XMSS_N;

    for (i = 0; i < XMSS_TREE_HEIGHT - 1; i++) {
        set_tree_height(addr, i);
        leafidx >>= 1;
        set_tree_index(addr, leafidx);
        if (leafidx & 1) {
            xmss_thash_h(buffer + XMSS_N, buffer, pub_seed, addr);
            memcpy(buffer, auth_path, XMSS_N);
        }
        else {
            xmss_thash_h(buffer, buffer, pub_seed, addr);
            memcpy(buffer + XMSS_N, auth_path, XMSS_N);
        }
        auth_path += XMSS_N;
    }
    set_tree_height(addr, XMSS_TREE_HEIGHT - 1);
    leafidx >>= 1;
    set_tree_index(addr, leafidx);
    xmss_thash_h(root, buffer, pub_seed, addr);
}

void xmss_gen_leaf_wots(unsigned char *leaf,
                   const unsigned char *sk_seed, const unsigned char *pub_seed,
                   uint32_t ltree_addr[8], uint32_t ots_addr[8])
{
    unsigned char pk[XMSS_WOTS_SIG_BYTES];
    xmss_wots_pkgen(pk, sk_seed, pub_seed, ots_addr);
    xmss_l_tree(leaf, pk, pub_seed, ltree_addr);
}

int xmss_core_sign_open(unsigned char *m, unsigned long long *mlen,
                        const unsigned char *sm, unsigned long long smlen,
                        const unsigned char *pk)
{
    return xmssmt_core_sign_open(m, mlen, sm, smlen, pk);
}

int xmssmt_core_sign_open(unsigned char *restrict m, unsigned long long *restrict mlen,
                          const unsigned char *restrict sm, unsigned long long smlen,
                          const unsigned char *restrict pk)
{
    if (smlen < XMSS_SIG_BYTES) {
        *mlen = 0;
        return -1;
    }

    const unsigned char *pub_root = pk;
    const unsigned char *pub_seed = pk + XMSS_N;
    unsigned char wots_pk[XMSS_WOTS_SIG_BYTES];
    unsigned char leaf[XMSS_N];
    unsigned char root[XMSS_N];
    unsigned char *mhash = root;

    unsigned long long idx = 0;
    unsigned int i;

    uint32_t idx_leaf;
    uint32_t ots_addr[8] = {0};
    uint32_t ltree_addr[8] = {0};
    uint32_t node_addr[8] = {0};

    set_type(ots_addr, XMSS_ADDR_TYPE_OTS);
    set_type(ltree_addr, XMSS_ADDR_TYPE_LTREE);
    set_type(node_addr, XMSS_ADDR_TYPE_HASHTREE);

    *mlen = smlen - XMSS_SIG_BYTES;
    idx = xmss_bytes_to_ull(sm, XMSS_INDEX_BYTES);
    memcpy(m + XMSS_SIG_BYTES, sm + XMSS_SIG_BYTES, *mlen);
    xmss_hash_message(mhash, sm + XMSS_INDEX_BYTES, pk, idx,
                 m + XMSS_SIG_BYTES - XMSS_PADDING_LEN - 3 * XMSS_N,
                 *mlen);
    sm += XMSS_INDEX_BYTES + XMSS_N;

    for (i = 0; i < XMSS_D; i++) {
        idx_leaf = (idx & ((1 << XMSS_TREE_HEIGHT) - 1));
        idx = idx >> XMSS_TREE_HEIGHT;
        set_layer_addr(ots_addr, i);
        set_layer_addr(ltree_addr, i);
        set_layer_addr(node_addr, i);
        set_tree_addr(ltree_addr, idx);
        set_tree_addr(ots_addr, idx);
        set_tree_addr(node_addr, idx);

        set_ots_addr(ots_addr, idx_leaf);
        wots_pk_from_sig(wots_pk, sm, root, pub_seed, ots_addr);
        sm += XMSS_WOTS_SIG_BYTES;

        set_ltree_addr(ltree_addr, idx_leaf);
        xmss_l_tree(leaf, wots_pk, pub_seed, ltree_addr);

        compute_root(root, leaf, idx_leaf, sm, pub_seed, node_addr);
        sm += XMSS_TREE_HEIGHT * XMSS_N;
    }

    if (memcmp(root, pub_root, XMSS_N)) {
        memset(m, 0, *mlen);
        *mlen = 0;
        return -1;
    }
    memcpy(m, sm, *mlen);
    return 0;
}
