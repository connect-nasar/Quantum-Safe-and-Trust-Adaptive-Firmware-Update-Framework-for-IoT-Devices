#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "XMSS_hash.h"
#include "XMSS_hash_address.h"
#include "XMSS_params.h"
#include "XMSS_randombytes.h"
#include "XMSS_wots.h"
#include "XMSS_utils.h"
#include "XMSS_commons.h"
#include "XMSS_core_fast.h"

/* Safe max index for full height > 63 */
#if XMSS_FULL_HEIGHT < 64
#define XMSS_MAX_INDEX ((1ULL << XMSS_FULL_HEIGHT) - 1)
#else
#define XMSS_MAX_INDEX (~0ULL)   /* all 64 bits set */
#endif
/* Maximum index within one XMSS subtree. */
#define XMSS_SINGLE_MAX_INDEX \
    ((1ULL << XMSS_TREE_HEIGHT) - 1ULL)

typedef struct {
    unsigned char h;
    unsigned long next_idx;
    unsigned char stackusage;
    unsigned char completed;
    unsigned char *node;
} treehash_inst;

typedef struct {
    unsigned char *stack;
    unsigned int stackoffset;
    unsigned char *stacklevels;
    unsigned char *auth;
    unsigned char *keep;
    treehash_inst *treehash;
    unsigned char *retain;
    unsigned int next_leaf;
} bds_state;

static void xmssmt_serialize_state(unsigned char *restrict sk, const bds_state *restrict states)
{
    unsigned int i, j;

    const size_t stack_size = (XMSS_TREE_HEIGHT + 1) * XMSS_N;
    const size_t stacklevels_size = XMSS_TREE_HEIGHT + 1;
    const size_t auth_size = XMSS_TREE_HEIGHT * XMSS_N;
    const size_t keep_size = (XMSS_TREE_HEIGHT >> 1) * XMSS_N;
    const size_t retain_size = ((1 << XMSS_BDS_K) - XMSS_BDS_K - 1) * XMSS_N;
    const unsigned int treehash_count = XMSS_TREE_HEIGHT - XMSS_BDS_K;
    
    unsigned char *ptr = sk + XMSS_INDEX_BYTES + 4 * XMSS_N;

    for (i = 0; i < 2 * XMSS_D - 1; i++) {
        memcpy(ptr, states[i].stack, stack_size);
        ptr += stack_size;
        xmss_ull_to_bytes(ptr, 4, states[i].stackoffset);
        ptr += 4;
        memcpy(ptr, states[i].stacklevels, stacklevels_size);
        ptr += stacklevels_size;
        memcpy(ptr, states[i].auth, auth_size);
        ptr += auth_size;
        memcpy(ptr, states[i].keep, keep_size);
        ptr += keep_size;
        for (j = 0; j < treehash_count; j++) {
            *ptr++ = states[i].treehash[j].h;

            xmss_ull_to_bytes(ptr, 4, states[i].treehash[j].next_idx);
            ptr += 4;
            *ptr++ = states[i].treehash[j].stackusage;
            *ptr++ = states[i].treehash[j].completed;
            memcpy(ptr, states[i].treehash[j].node, XMSS_N);
            ptr += XMSS_N;
        }
        memcpy(ptr, states[i].retain, retain_size);

        ptr += retain_size;
        xmss_ull_to_bytes(ptr, 4, states[i].next_leaf);
        ptr += 4;
    }
}



static void xmssmt_deserialize_state(
    bds_state *restrict states,
    unsigned char **restrict wots_sigs,
    unsigned char *restrict sk)
{
    
    // This avoids re-calculating these constants inside the loop.
    const size_t stack_size = (XMSS_TREE_HEIGHT + 1) * XMSS_N;
    const size_t stacklevels_size = XMSS_TREE_HEIGHT + 1;
    const size_t auth_size = XMSS_TREE_HEIGHT * XMSS_N;
    const size_t keep_size = (XMSS_TREE_HEIGHT >> 1) * XMSS_N;
    const size_t retain_size = ((1 << XMSS_BDS_K) - XMSS_BDS_K - 1) * XMSS_N;
    const unsigned int treehash_count = XMSS_TREE_HEIGHT - XMSS_BDS_K;

    unsigned char *ptr = sk + XMSS_INDEX_BYTES + 4 * XMSS_N;

    for (unsigned int i = 0; i < 2 * XMSS_D - 1; i++) {
        states[i].stack = ptr;
        ptr += stack_size;
        
        states[i].stackoffset = xmss_bytes_to_ull(ptr, 4);
        ptr += 4;
        
        states[i].stacklevels = ptr;
        ptr += stacklevels_size;
        
        states[i].auth = ptr;
        ptr += auth_size;
        
        states[i].keep = ptr;
        ptr += keep_size;

        for (unsigned int j = 0; j < treehash_count; j++) {
            
            states[i].treehash[j].h = *ptr++;
            states[i].treehash[j].next_idx = xmss_bytes_to_ull(ptr, 4);
            ptr += 4;
            states[i].treehash[j].stackusage = *ptr++;
            states[i].treehash[j].completed = *ptr++;
            states[i].treehash[j].node = ptr;
            ptr += XMSS_N;
        }

        // --- Map remaining state parts ---
        states[i].retain = ptr;
        ptr += retain_size;
        
        states[i].next_leaf = xmss_bytes_to_ull(ptr, 4);
        ptr += 4;
    }

    if (XMSS_D > 1) {
        *wots_sigs = ptr;
    }
}

static void xmss_serialize_state(unsigned char *sk, bds_state *state)
{
    xmssmt_serialize_state(sk, state);
}

static void xmss_deserialize_state(bds_state *state, unsigned char *sk)
{
    xmssmt_deserialize_state(state, NULL, sk);
}

static inline void xmss_memswap(void *restrict a, void *restrict b, void *restrict t, unsigned long long len)
{


    memcpy(t, a, len);
    memcpy(a, b, len);
    memcpy(b, t, len);
}

static void xmss_deep_state_swap(bds_state *restrict a, bds_state *restrict b)
{
    unsigned char t[
        ((XMSS_TREE_HEIGHT + 1) > ((1 << XMSS_BDS_K) - XMSS_BDS_K - 1)
         ? (XMSS_TREE_HEIGHT + 1)
         : ((1 << XMSS_BDS_K) - XMSS_BDS_K - 1))
        * XMSS_N];
    unsigned int i;
    xmss_memswap(a->stack, b->stack, t, (XMSS_TREE_HEIGHT + 1) * XMSS_N);
    xmss_memswap(&a->stackoffset, &b->stackoffset, t, sizeof(a->stackoffset));
    xmss_memswap(a->stacklevels, b->stacklevels, t, XMSS_TREE_HEIGHT + 1);
    xmss_memswap(a->auth, b->auth, t, XMSS_TREE_HEIGHT * XMSS_N);
    xmss_memswap(a->keep, b->keep, t, (XMSS_TREE_HEIGHT >> 1) * XMSS_N);
    for (i = 0; i < XMSS_TREE_HEIGHT - XMSS_BDS_K; i++) {
        xmss_memswap(&a->treehash[i].h, &b->treehash[i].h, t, sizeof(a->treehash[i].h));
        xmss_memswap(&a->treehash[i].next_idx, &b->treehash[i].next_idx, t, sizeof(a->treehash[i].next_idx));
        xmss_memswap(&a->treehash[i].stackusage, &b->treehash[i].stackusage, t, sizeof(a->treehash[i].stackusage));
        xmss_memswap(&a->treehash[i].completed, &b->treehash[i].completed, t, sizeof(a->treehash[i].completed));
        xmss_memswap(a->treehash[i].node, b->treehash[i].node, t, XMSS_N);
    }
    xmss_memswap(a->retain, b->retain, t, ((1 << XMSS_BDS_K) - XMSS_BDS_K - 1) * XMSS_N);
    xmss_memswap(&a->next_leaf, &b->next_leaf, t, sizeof(a->next_leaf));
}

static int treehash_minheight_on_stack(bds_state *state,
                                       const treehash_inst *treehash)
{
    unsigned int r = XMSS_TREE_HEIGHT, i;
    for (i = 0; i < treehash->stackusage; i++) {
        if (state->stacklevels[state->stackoffset - i - 1] < r) {
            r = state->stacklevels[state->stackoffset - i - 1];
        }
    }
    return r;
}

static void xmss_treehash_init(
    unsigned char *restrict node,
    int height,
    int index,
    bds_state *restrict state,
    const unsigned char *restrict sk_seed,
    const unsigned char *restrict pub_seed,
    const uint32_t addr[restrict 8])
{
    const unsigned int treehash_count =
        XMSS_TREE_HEIGHT - XMSS_BDS_K;


    const unsigned int start_idx = (unsigned int)index;
    const unsigned int leaf_count = 1U << (unsigned int)height;
    const unsigned int end_idx = start_idx + leaf_count;


    uint32_t ots_addr[8]   = {0};
    uint32_t ltree_addr[8] = {0};
    uint32_t node_addr[8]  = {0};

    unsigned char stack[(XMSS_TREE_HEIGHT + 1U) * XMSS_N];

    /*
     * Only heights from 0 to XMSS_TREE_HEIGHT are stored.
     * uint8_t is sufficient for supported XMSS tree heights.
     */
    uint8_t stacklevels[XMSS_TREE_HEIGHT + 1U];

    unsigned int stackoffset = 0U;
    unsigned int idx;
    unsigned int leaf_offset;
    unsigned int th_index;


    copy_subtree_addr(ots_addr, addr);
    set_type(ots_addr, 0U);

    copy_subtree_addr(ltree_addr, addr);
    set_type(ltree_addr, 1U);

    copy_subtree_addr(node_addr, addr);
    set_type(node_addr, 2U);

    /* Initialize every BDS TreeHash instance. */
    for (th_index = 0U; th_index < treehash_count; ++th_index) {
        treehash_inst *const th = &state->treehash[th_index];

        th->h = th_index;
        th->completed = 1;
        th->stackusage = 0;
    }


    for (idx = start_idx, leaf_offset = 0U;
     idx < end_idx;
     ++idx, ++leaf_offset) {
        unsigned char *const leaf =
            stack + stackoffset * XMSS_N;

        set_ltree_addr(ltree_addr, idx);
        set_ots_addr(ots_addr, idx);

        xmss_gen_leaf_wots(
            leaf,
            sk_seed,
            pub_seed,
            ltree_addr,
            ots_addr);

        stacklevels[stackoffset] = 0U;
        ++stackoffset;

        /*
         * 
         *
         * This points to the next free stack position after stackoffset
         * was incremented. Do not remove it until deterministic state
         * comparison confirms that it is unnecessary.
         */
        if (treehash_count != 0U && leaf_offset == 3U) {
            memcpy( state->treehash[0].node,leaf,XMSS_N);
        }

        while (stackoffset > 1U) {
            const unsigned int right_position = stackoffset - 1U;
            const unsigned int left_position  = stackoffset - 2U;

            if (stacklevels[left_position] !=
                stacklevels[right_position]) {
                break;
}

            unsigned char *const left_node =
                stack + left_position * XMSS_N;

            const unsigned char *const right_node =
                left_node + XMSS_N;

            const unsigned int node_height =
            stacklevels[right_position];

            const unsigned int node_position =
            leaf_offset >> node_height;




            if (node_position == 1U) {
                memcpy(
                    state->auth + node_height * XMSS_N,
                    right_node,
                    XMSS_N);
            } else {
                if (node_height < treehash_count &&
                    node_position == 3U) {
                    memcpy(
                        state->treehash[node_height].node,
                        right_node,
                        XMSS_N);
                } else if (node_height >= treehash_count) {
                    const unsigned int retain_index =
                        (1U << (XMSS_TREE_HEIGHT - 1U - node_height))
                        + node_height
                        - XMSS_TREE_HEIGHT
                        + ((node_position - 3U) >> 1U);

                    memcpy(
                        state->retain + retain_index * XMSS_N,
                        right_node,
                        XMSS_N);
                }
            }

            set_tree_height(node_addr, node_height);
            set_tree_index(
                node_addr,
                idx >> (node_height + 1U));

            /*
             * left_node and right_node are adjacent in stack.
             * The parent overwrites the left node.
             */
            xmss_thash_h(
                left_node,
                left_node,
                pub_seed,
                node_addr);

            stacklevels[left_position] =
                (uint8_t)(node_height + 1U);

            --stackoffset;
        }

        
    }

    memcpy(node, stack, XMSS_N);
}

static void xmss_treehash_update(treehash_inst *treehash, bds_state *state,
                            const unsigned char *restrict sk_seed,
                            const unsigned char *restrict pub_seed,
                            const uint32_t addr[restrict 8])
{
    uint32_t ots_addr[8] = {0};
    uint32_t ltree_addr[8] = {0};
    uint32_t node_addr[8] = {0};

    copy_subtree_addr(ots_addr, addr);
    set_type(ots_addr, 0);
    copy_subtree_addr(ltree_addr, addr);
    set_type(ltree_addr, 1);
    copy_subtree_addr(node_addr, addr);
    set_type(node_addr, 2);

    const unsigned int next_idx = treehash->next_idx;

    set_ltree_addr(ltree_addr, next_idx);
    set_ots_addr(ots_addr, next_idx);

    unsigned char nodebuffer[2 * XMSS_N];
    unsigned int nodeheight = 0;
    xmss_gen_leaf_wots(nodebuffer, sk_seed, pub_seed, ltree_addr, ots_addr);

    while (treehash->stackusage > 0) {
        const unsigned int top_position = state->stackoffset - 1;

        if (state->stacklevels[top_position] != nodeheight) {
            break;
        }

        memcpy(nodebuffer + XMSS_N, nodebuffer, XMSS_N);
        memcpy(nodebuffer, state->stack + top_position * XMSS_N, XMSS_N);
        set_tree_height(node_addr, nodeheight);
        set_tree_index(node_addr, (next_idx >> (nodeheight + 1)));
        xmss_thash_h(nodebuffer, nodebuffer, pub_seed, node_addr);
        nodeheight++;
        treehash->stackusage--;
        state->stackoffset--;
    }

    if (nodeheight == treehash->h) {
        memcpy(treehash->node, nodebuffer, XMSS_N);
        treehash->completed = 1;
    }
    else {
        const unsigned int stackoffset = state->stackoffset;

        memcpy(state->stack + stackoffset * XMSS_N, nodebuffer, XMSS_N);
        treehash->stackusage++;
        state->stacklevels[stackoffset] = nodeheight;
        state->stackoffset++;
        treehash->next_idx = next_idx + 1;
    }
}

static char xmss_bds_treehash_update(bds_state *state, unsigned int updates,
                                const unsigned char *restrict sk_seed,
                                const unsigned char *restrict pub_seed,
                                const uint32_t addr[restrict 8])
{
    const unsigned int treehash_count = XMSS_TREE_HEIGHT - XMSS_BDS_K;
    treehash_inst *const treehash = state->treehash;
    unsigned int used = 0;

    while (used < updates) {
        unsigned int level = treehash_count;
        unsigned int l_min = XMSS_TREE_HEIGHT;
        unsigned int i;

        for (i = 0; i < treehash_count; i++) {
            treehash_inst *const current = &treehash[i];
            unsigned int low;

            if (current->completed) {
                continue;
            }
            if (current->stackusage == 0) {
                low = i;
            }
            else {
                low = treehash_minheight_on_stack(state, current);
            }

            if (low < l_min) {
                level = i;
                l_min = low;
            }
        }

        if (level == treehash_count) {
            break;
        }

        xmss_treehash_update(&treehash[level], state,
                                 sk_seed, pub_seed, addr);
        used++;
    }

    return (char)(updates - used);
}

static char xmss_bds_state_update(bds_state *restrict state,
                             const unsigned char *restrict sk_seed,
                             const unsigned char *restrict pub_seed,
                             const uint32_t addr[restrict 8])
{
    uint32_t ltree_addr[8] = {0};
    uint32_t node_addr[8] = {0};
    uint32_t ots_addr[8] = {0};
    unsigned int nodeh;
    int idx = state->next_leaf;

    if (idx == 1 << XMSS_TREE_HEIGHT) {
        return -1;
    }

    copy_subtree_addr(ots_addr, addr);
    set_type(ots_addr, 0);
    copy_subtree_addr(ltree_addr, addr);
    set_type(ltree_addr, 1);
    copy_subtree_addr(node_addr, addr);
    set_type(node_addr, 2);

    set_ots_addr(ots_addr, idx);
    set_ltree_addr(ltree_addr, idx);

     unsigned char *stack_ptr = state->stack + state->stackoffset * XMSS_N;

    xmss_gen_leaf_wots(stack_ptr, sk_seed, pub_seed, ltree_addr, ots_addr);
    state->stacklevels[state->stackoffset] = 0;
    state->stackoffset++;

    if (XMSS_TREE_HEIGHT - XMSS_BDS_K > 0 && idx == 3) {
        memcpy(state->treehash[0].node, stack_ptr, XMSS_N);
    }
    while (state->stackoffset > 1 && state->stacklevels[state->stackoffset - 1] == state->stacklevels[state->stackoffset - 2]) {

        unsigned char *right_node = state->stack + (state->stackoffset - 1) * XMSS_N;
        unsigned char *left_node = right_node - XMSS_N;
        

        nodeh = state->stacklevels[state->stackoffset - 1];
        if (idx >> nodeh == 1) {
            memcpy(state->auth + nodeh * XMSS_N, right_node, XMSS_N);
        }
        else {
            if (nodeh < XMSS_TREE_HEIGHT - XMSS_BDS_K && idx >> nodeh == 3) {
                memcpy(state->treehash[nodeh].node, right_node, XMSS_N);
            }
            else if (nodeh >= XMSS_TREE_HEIGHT - XMSS_BDS_K) {
                const unsigned int retain_offset = (1 << (XMSS_TREE_HEIGHT - 1 - nodeh)) + nodeh - XMSS_TREE_HEIGHT;
                const unsigned int retain_idx = retain_offset + (((idx >> nodeh) - 3) >> 1);

                memcpy(state->retain + retain_idx * XMSS_N, right_node, XMSS_N);
            }
        }
        set_tree_height(node_addr, nodeh);
        set_tree_index(node_addr, (idx >> (nodeh + 1)));
        xmss_thash_h(left_node, left_node, pub_seed, node_addr);
        
        state->stacklevels[state->stackoffset - 2]++;
        state->stackoffset--;
    }
    state->next_leaf++;
    return 0;
}

static void xmss_bds_round(bds_state *restrict state, const unsigned long leaf_idx,
                      const unsigned char *restrict sk_seed,
                      const unsigned char *restrict pub_seed, uint32_t addr[restrict 8])
{
    unsigned int i;
    unsigned int tau = XMSS_TREE_HEIGHT;
    unsigned int startidx;
    unsigned int offset, rowidx;
    unsigned char buf[2 * XMSS_N]; 
    uint32_t ots_addr[8] = {0};
    uint32_t ltree_addr[8] = {0};
    uint32_t node_addr[8] = {0};

    copy_subtree_addr(ots_addr, addr);
    set_type(ots_addr, 0);
    copy_subtree_addr(ltree_addr, addr);
    set_type(ltree_addr, 1);
    copy_subtree_addr(node_addr, addr);
    set_type(node_addr, 2);

    for (i = 0; i < XMSS_TREE_HEIGHT; i++) {
        if (!((leaf_idx >> i) & 1)) {
            tau = i;
            break;
        }
    }

    if (tau > 0) {
        unsigned char *auth_ptr = state->auth + (tau - 1) * XMSS_N;
        unsigned char *keep_ptr = state->keep + ((tau - 1) >> 1) * XMSS_N;

        memcpy(buf, auth_ptr, XMSS_N);
        memcpy(buf + XMSS_N, keep_ptr, XMSS_N);
    }
    if (!((leaf_idx >> (tau + 1)) & 1) && (tau < XMSS_TREE_HEIGHT - 1)) {
        unsigned char *dest_keep_ptr = state->keep + (tau >> 1) * XMSS_N;
        unsigned char *src_auth_ptr = state->auth + tau * XMSS_N;

        memcpy(dest_keep_ptr, src_auth_ptr, XMSS_N);
    }
    if (tau == 0) {
        set_ltree_addr(ltree_addr, leaf_idx);
        set_ots_addr(ots_addr, leaf_idx);
        xmss_gen_leaf_wots(state->auth, sk_seed, pub_seed, ltree_addr, ots_addr);
    }
    else {
        set_tree_height(node_addr, (tau - 1));
        set_tree_index(node_addr, leaf_idx >> tau);
        unsigned char *dest_auth_tau = state->auth + tau * XMSS_N;

        xmss_thash_h(dest_auth_tau, buf, pub_seed, node_addr);
        unsigned char *auth_ptr = state->auth;

        for (i = 0; i < tau; i++) {
            if (i < XMSS_TREE_HEIGHT - XMSS_BDS_K) {
                memcpy(auth_ptr, state->treehash[i].node, XMSS_N);
            }
            else {
                offset = (1 << (XMSS_TREE_HEIGHT - 1 - i)) + i - XMSS_TREE_HEIGHT;
                rowidx = ((leaf_idx >> i) - 1) >> 1;
                memcpy(auth_ptr, state->retain + (offset + rowidx) * XMSS_N, XMSS_N);
            }
            auth_ptr += XMSS_N;
        }
        for (i = 0; i < ((tau < XMSS_TREE_HEIGHT - XMSS_BDS_K) ? tau : (XMSS_TREE_HEIGHT - XMSS_BDS_K)); i++) {
            startidx = leaf_idx + 1 + 3 * (1 << i);
            if (startidx < 1U << XMSS_TREE_HEIGHT) {
                state->treehash[i].h = i;
                state->treehash[i].next_idx = startidx;
                state->treehash[i].completed = 0;
                state->treehash[i].stackusage = 0;
            }
        }
    }
}

unsigned long long xmss_xmssmt_core_sk_bytes(void)
{
    return XMSS_INDEX_BYTES + 4 * XMSS_N
        + (2 * XMSS_D - 1) * (
            (XMSS_TREE_HEIGHT + 1) * XMSS_N
            + 4
            + XMSS_TREE_HEIGHT + 1
            + XMSS_TREE_HEIGHT * XMSS_N
            + (XMSS_TREE_HEIGHT >> 1) * XMSS_N
            + (XMSS_TREE_HEIGHT - XMSS_BDS_K) * (7 + XMSS_N)
            + ((1 << XMSS_BDS_K) - XMSS_BDS_K - 1) * XMSS_N
            + 4
         )
        + (XMSS_D - 1) * XMSS_WOTS_SIG_BYTES;
}

int xmss_fast_keypair(unsigned char *pk, unsigned char *sk)
{
    uint32_t addr[8] = {0};
    bds_state state;
    treehash_inst treehash[XMSS_TREE_HEIGHT - XMSS_BDS_K];
    state.treehash = treehash;

    xmss_deserialize_state(&state, sk);
    state.stackoffset = 0;
    state.next_leaf = 0;

    sk[0] = 0;
    sk[1] = 0;
    sk[2] = 0;
    sk[3] = 0;

    randombytes(sk + XMSS_INDEX_BYTES, 2 * XMSS_N);
    randombytes(sk + XMSS_INDEX_BYTES + 3 * XMSS_N, XMSS_N);
    memcpy(pk + XMSS_N, sk + XMSS_INDEX_BYTES + 3 * XMSS_N, XMSS_N);

    xmss_treehash_init(pk, XMSS_TREE_HEIGHT, 0, &state, sk + XMSS_INDEX_BYTES, sk + XMSS_INDEX_BYTES + 3 * XMSS_N, addr);
    memcpy(sk + XMSS_INDEX_BYTES + 2 * XMSS_N, pk, XMSS_N);

    xmss_serialize_state(sk, &state);
    return 0;
}

int xmss_fast_sign(unsigned char *sk,
                   unsigned char *sm, unsigned long long *smlen,
                   const unsigned char *m, unsigned long long mlen)
{
    const unsigned char *pub_root = sk + XMSS_INDEX_BYTES + 2 * XMSS_N;
    uint16_t i = 0;
    bds_state state;
    treehash_inst treehash[XMSS_TREE_HEIGHT - XMSS_BDS_K];
    state.treehash = treehash;

    xmss_deserialize_state(&state, sk);
    unsigned long idx = ((unsigned long)sk[0] << 24) | ((unsigned long)sk[1] << 16) | ((unsigned long)sk[2] << 8) | sk[3];

    if ((uint64_t)idx >= XMSS_SINGLE_MAX_INDEX) {
    memset(sk, 0xFF, XMSS_INDEX_BYTES);
    memset(sk + XMSS_INDEX_BYTES, 0,
           xmss_xmssmt_core_sk_bytes() - XMSS_INDEX_BYTES);

    if ((uint64_t)idx > XMSS_SINGLE_MAX_INDEX) {
        return -2;
    }
}

    unsigned char sk_seed[XMSS_N];
    memcpy(sk_seed, sk + XMSS_INDEX_BYTES, XMSS_N);
    unsigned char sk_prf[XMSS_N];
    memcpy(sk_prf, sk + XMSS_INDEX_BYTES + XMSS_N, XMSS_N);
    unsigned char pub_seed[XMSS_N];
    memcpy(pub_seed, sk + XMSS_INDEX_BYTES + 3 * XMSS_N, XMSS_N);

    unsigned char idx_bytes_32[32];
    xmss_ull_to_bytes(idx_bytes_32, 32, idx);

    sk[0] = ((idx + 1) >> 24) & 255;
    sk[1] = ((idx + 1) >> 16) & 255;
    sk[2] = ((idx + 1) >> 8) & 255;
    sk[3] = (idx + 1) & 255;

    unsigned char R[XMSS_N];
    unsigned char msg_h[XMSS_N];
    uint32_t ots_addr[8] = {0};

    xmss_prf(R, idx_bytes_32, sk_prf);
    memcpy(sm + XMSS_SIG_BYTES, m, mlen);
    xmss_hash_message(msg_h, R, pub_root, idx,
                 sm + XMSS_SIG_BYTES - XMSS_PADDING_LEN - 3 * XMSS_N,
                 mlen);

    *smlen = 0;
    sm[0] = (idx >> 24) & 255;
    sm[1] = (idx >> 16) & 255;
    sm[2] = (idx >> 8) & 255;
    sm[3] = idx & 255;
    sm += 4;
    *smlen += 4;

    for (i = 0; i < XMSS_N; i++) {
        sm[i] = R[i];
    }
    sm += XMSS_N;
    *smlen += XMSS_N;

    set_type(ots_addr, 0);
    set_ots_addr(ots_addr, idx);

    xmss_wots_sign(sm, msg_h, sk_seed, pub_seed, ots_addr);
    sm += XMSS_WOTS_SIG_BYTES;
    *smlen += XMSS_WOTS_SIG_BYTES;

    memcpy(sm, state.auth, XMSS_TREE_HEIGHT * XMSS_N);
    if (idx < (1U << XMSS_TREE_HEIGHT) - 1) {
        xmss_bds_round(&state, idx, sk_seed, pub_seed, ots_addr);
        xmss_bds_treehash_update(&state, (XMSS_TREE_HEIGHT - XMSS_BDS_K) >> 1, sk_seed, pub_seed, ots_addr);
    }
    sm += XMSS_TREE_HEIGHT * XMSS_N;
    *smlen += XMSS_TREE_HEIGHT * XMSS_N;

    memcpy(sm, m, mlen);
    *smlen += mlen;

    xmss_serialize_state(sk, &state);
    return 0;
}

int xmssmt_fast_keypair(unsigned char *pk, unsigned char *sk)
{
    uint32_t addr[8] = {0};
    unsigned int i;
    unsigned char *wots_sigs;
    bds_state states[2 * XMSS_D];   // +1 extra for safety
    treehash_inst treehash[(2 * XMSS_D) * (XMSS_TREE_HEIGHT - XMSS_BDS_K)];
    for (i = 0; i < 2 * XMSS_D - 1; i++) {
        states[i].treehash = treehash + i * (XMSS_TREE_HEIGHT - XMSS_BDS_K);
    }
    xmssmt_deserialize_state(states, &wots_sigs, sk);

    for (i = 0; i < 2 * XMSS_D - 1; i++) {
        states[i].stackoffset = 0;
        states[i].next_leaf = 0;
    }

    for (i = 0; i < XMSS_INDEX_BYTES; i++) {
        sk[i] = 0;
    }

    randombytes(sk + XMSS_INDEX_BYTES, 2 * XMSS_N);
    randombytes(sk + XMSS_INDEX_BYTES + 3 * XMSS_N, XMSS_N);
    memcpy(pk + XMSS_N, sk + XMSS_INDEX_BYTES + 3 * XMSS_N, XMSS_N);

    set_layer_addr(addr, 0);

    for (i = 0; i + 1 < XMSS_D; i++) {
        xmss_treehash_init(pk, XMSS_TREE_HEIGHT, 0, states + i, sk + XMSS_INDEX_BYTES, pk + XMSS_N, addr);
        set_layer_addr(addr, (i + 1));
        xmss_wots_sign(wots_sigs + i * XMSS_WOTS_SIG_BYTES, pk, sk + XMSS_INDEX_BYTES, pk + XMSS_N, addr);
    }

    xmss_treehash_init(pk, XMSS_TREE_HEIGHT, 0, states + i, sk + XMSS_INDEX_BYTES, pk + XMSS_N, addr);
    memcpy(sk + XMSS_INDEX_BYTES + 2 * XMSS_N, pk, XMSS_N);

    xmssmt_serialize_state(sk, states);
    return 0;
}

int xmssmt_fast_sign(unsigned char *restrict sk,
                     unsigned char *restrict sm, unsigned long long *restrict smlen,
                     const unsigned char *restrict m, unsigned long long mlen)
{
    const unsigned char *pub_root = sk + XMSS_INDEX_BYTES + 2 * XMSS_N;
    uint64_t idx_tree;
    uint32_t idx_leaf;
    uint64_t i, j;
    int needswap_upto = -1;
    unsigned int updates;
    unsigned char sk_seed[XMSS_N];
    unsigned char sk_prf[XMSS_N];
    unsigned char pub_seed[XMSS_N];

    unsigned char R[XMSS_N];
    unsigned char msg_h[XMSS_N];
    uint32_t addr[8] = {0};
    uint32_t ots_addr[8] = {0};
    unsigned char idx_bytes_32[32];
    unsigned char *wots_sigs;

    bds_state states[2 * XMSS_D];
    treehash_inst treehash[(2 * XMSS_D) * (XMSS_TREE_HEIGHT - XMSS_BDS_K)];
    for (i = 0; i < 2 * XMSS_D - 1; i++) {
        states[i].treehash = treehash + i * (XMSS_TREE_HEIGHT - XMSS_BDS_K);
    }
    xmssmt_deserialize_state(states, &wots_sigs, sk);

    unsigned long long idx = 0;
    for (i = 0; i < XMSS_INDEX_BYTES; i++) {
        idx |= ((unsigned long long)sk[i]) << 8 * (XMSS_INDEX_BYTES - 1 - i);
    }

    if (idx >= XMSS_MAX_INDEX) {
    if (idx > XMSS_MAX_INDEX) {
        // Key is already fully used up. Destroy it and refuse to sign.
        memset(sk, 0, xmss_xmssmt_core_sk_bytes());
        return -2; // Return error
    }
    // If idx == XMSS_MAX_INDEX, we allow this one last signature to proceed.
    // The key will be destroyed at the VERY END of the function.
    }

    memcpy(sk_seed, sk + XMSS_INDEX_BYTES, XMSS_N);
    memcpy(sk_prf, sk + XMSS_INDEX_BYTES + XMSS_N, XMSS_N);
    memcpy(pub_seed, sk + XMSS_INDEX_BYTES + 3 * XMSS_N, XMSS_N);

    for (i = 0; i < XMSS_INDEX_BYTES; i++) {
        sk[i] = ((idx + 1) >> 8 * (XMSS_INDEX_BYTES - 1 - i)) & 255;
    }

    xmss_ull_to_bytes(idx_bytes_32, 32, idx);
    xmss_prf(R, idx_bytes_32, sk_prf);
    memcpy(sm + XMSS_SIG_BYTES, m, mlen);
    xmss_hash_message(msg_h, R, pub_root, idx,
                 sm + XMSS_SIG_BYTES - XMSS_PADDING_LEN - 3 * XMSS_N,
                 mlen);

    *smlen = 0;
    for (i = 0; i < XMSS_INDEX_BYTES; i++) {
        sm[i] = (idx >> 8 * (XMSS_INDEX_BYTES - 1 - i)) & 255;
    }
    sm += XMSS_INDEX_BYTES;
    *smlen += XMSS_INDEX_BYTES;

    for (i = 0; i < XMSS_N; i++) {
        sm[i] = R[i];
    }
    sm += XMSS_N;
    *smlen += XMSS_N;

    set_type(ots_addr, 0);
    idx_tree = idx >> XMSS_TREE_HEIGHT;
    idx_leaf = (idx & ((1 << XMSS_TREE_HEIGHT) - 1));
    set_layer_addr(ots_addr, 0);
    set_tree_addr(ots_addr, idx_tree);
    set_ots_addr(ots_addr, idx_leaf);

    xmss_wots_sign(sm, msg_h, sk_seed, pub_seed, ots_addr);
    sm += XMSS_WOTS_SIG_BYTES;
    *smlen += XMSS_WOTS_SIG_BYTES;
    memcpy(sm, states[0].auth, XMSS_TREE_HEIGHT * XMSS_N);
    sm += XMSS_TREE_HEIGHT * XMSS_N;
    *smlen += XMSS_TREE_HEIGHT * XMSS_N;

    for (i = 1; i < XMSS_D; i++) {
        memcpy(sm, wots_sigs + (i - 1) * XMSS_WOTS_SIG_BYTES, XMSS_WOTS_SIG_BYTES);
        sm += XMSS_WOTS_SIG_BYTES;
        *smlen += XMSS_WOTS_SIG_BYTES;
        memcpy(sm, states[i].auth, XMSS_TREE_HEIGHT * XMSS_N);
        sm += XMSS_TREE_HEIGHT * XMSS_N;
        *smlen += XMSS_TREE_HEIGHT * XMSS_N;
    }

    updates = (XMSS_TREE_HEIGHT - XMSS_BDS_K) >> 1;
    set_tree_addr(addr, (idx_tree + 1));

    if ((1 + idx_tree) * (1 << XMSS_TREE_HEIGHT) + idx_leaf < (XMSS_MAX_INDEX + 1)) {
        xmss_bds_state_update(&states[XMSS_D], sk_seed, pub_seed, addr);
    }

    for (i = 0; i < XMSS_D; i++) {
        if (!(((idx + 1) & ((1ULL << ((i + 1) * XMSS_TREE_HEIGHT)) - 1)) == 0)) {
            idx_leaf = (idx >> (XMSS_TREE_HEIGHT * i)) & ((1 << XMSS_TREE_HEIGHT) - 1);
            idx_tree = (idx >> (XMSS_TREE_HEIGHT * (i + 1)));
            set_layer_addr(addr, i);
            set_tree_addr(addr, idx_tree);
            if (i == (unsigned int)(needswap_upto + 1)) {
                xmss_bds_round(&states[i], idx_leaf, sk_seed, pub_seed, addr);
            }
            updates = xmss_bds_treehash_update(&states[i], updates, sk_seed, pub_seed, addr);
            set_tree_addr(addr, (idx_tree + 1));
            if ((1 + idx_tree) * (1 << XMSS_TREE_HEIGHT) + idx_leaf < (1ULL << (XMSS_FULL_HEIGHT - XMSS_TREE_HEIGHT * i))) {
                if (i > 0 && updates > 0 &&(uint64_t)states[XMSS_D + i].next_leaf <(1ULL << XMSS_TREE_HEIGHT)) {
                    xmss_bds_state_update(&states[XMSS_D + i], sk_seed, pub_seed, addr);
                    updates--;
                }
            }
        }
        else if (idx < XMSS_MAX_INDEX) {
            xmss_deep_state_swap(states + XMSS_D + i, states + i);
            set_layer_addr(ots_addr, (i + 1));
            set_tree_addr(ots_addr, ((idx + 1) >> ((i + 2) * XMSS_TREE_HEIGHT)));
            set_ots_addr(ots_addr, (((idx >> ((i + 1) * XMSS_TREE_HEIGHT)) + 1) & ((1 << XMSS_TREE_HEIGHT) - 1)));
            xmss_wots_sign(wots_sigs + i * XMSS_WOTS_SIG_BYTES, states[i].stack, sk_seed, pub_seed, ots_addr);
            states[XMSS_D + i].stackoffset = 0;
            states[XMSS_D + i].next_leaf = 0;
            updates--;
            needswap_upto = i;
            for (j = 0; j < XMSS_TREE_HEIGHT - XMSS_BDS_K; j++) {
                states[i].treehash[j].completed = 1;
            }
        }
    }

    memcpy(sm, m, mlen);
    *smlen += mlen;
    

    if (idx == XMSS_MAX_INDEX) {
        memset(sk, 0, xmss_xmssmt_core_sk_bytes());
    } 
    else {
    // Otherwise, save the updated state for the next signature.
    xmssmt_serialize_state(sk, states);
    }
    return 0;
}
