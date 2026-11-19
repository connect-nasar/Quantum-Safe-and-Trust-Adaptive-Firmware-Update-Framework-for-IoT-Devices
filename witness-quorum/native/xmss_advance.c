/* Application adapter: use the canonical BDS transition without producing a
 * WOTS signature. The shared algorithm files stay in crypto-libs/xmss.
 * Compiled only for the deployed XMSS_MODE=1 profile. */
#include "XMSS_core_fast.c"

#if XMSS_D != 1 || XMSS_INDEX_BYTES != 4 || XMSS_N != 32 || XMSS_TREE_HEIGHT != 10
#error "Witness state advancement supports the deployed XMSS_MODE=1 only"
#endif

int witness_xmss_advance(unsigned char *sk)
{
    const unsigned long idx = xmss_bytes_to_ull(sk, XMSS_INDEX_BYTES);
    bds_state state;
    treehash_inst treehash[XMSS_TREE_HEIGHT - XMSS_BDS_K];
    uint32_t addr[8] = {0};
    /* Reserve the final leaf to avoid the legacy final-leaf destruction path. */
    if (idx >= 1023UL) return -2;
    state.treehash = treehash;
    xmss_deserialize_state(&state, sk);
    set_type(addr, 0);
    set_ots_addr(addr, idx);
    xmss_bds_round(&state, idx, sk + XMSS_INDEX_BYTES,
                   sk + XMSS_INDEX_BYTES + 3 * XMSS_N, addr);
    xmss_bds_treehash_update(&state, (XMSS_TREE_HEIGHT - XMSS_BDS_K) >> 1,
                            sk + XMSS_INDEX_BYTES,
                            sk + XMSS_INDEX_BYTES + 3 * XMSS_N, addr);
    xmss_ull_to_bytes(sk, XMSS_INDEX_BYTES, idx + 1UL);
    xmss_serialize_state(sk, &state);
    return 0;
}
