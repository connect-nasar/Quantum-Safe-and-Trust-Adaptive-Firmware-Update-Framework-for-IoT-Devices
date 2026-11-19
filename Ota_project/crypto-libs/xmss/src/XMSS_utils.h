#ifndef XMSS_UTILS_H
#define XMSS_UTILS_H

/**
 * Converts the value of 'in' to 'outlen' bytes in big-endian byte order.
 */
// void xmss_ull_to_bytes(unsigned char *out, unsigned int outlen,
//                   unsigned long long in);

static inline void xmss_ull_to_bytes(unsigned char *restrict out, unsigned int outlen,
                  unsigned long long in)
{
    int i;
    /* Iterate over out in decreasing order, for big-endianness. */
    for (i = outlen - 1; i >= 0; i--) {
        out[i] = in & 0xff;
        in = in >> 8;
    }
}


/**
 * Converts the inlen bytes in 'in' from big-endian byte order to an integer.
 */

static inline unsigned long long xmss_bytes_to_ull(const unsigned char *restrict in, unsigned int inlen)
{
    unsigned long long retval = 0;
    unsigned int i;
    for (i = 0; i < inlen; i++) {
        retval |= ((unsigned long long)in[i]) << (8 * (inlen - 1 - i));
    }
    return retval;
}


#endif /* XMSS_UTILS_H */
