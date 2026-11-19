#include <stdint.h>



void set_key_and_mask(uint32_t addr[8], uint32_t key_and_mask)
{
    addr[7] = key_and_mask;
}

void copy_subtree_addr(uint32_t out[8], const uint32_t in[8])
{
    out[0] = in[0];
    out[1] = in[1];
    out[2] = in[2];
}




/* This function is used for L-tree addresses. */

void set_ltree_addr(uint32_t addr[8], uint32_t ltree)
{
    addr[4] = ltree;
}


