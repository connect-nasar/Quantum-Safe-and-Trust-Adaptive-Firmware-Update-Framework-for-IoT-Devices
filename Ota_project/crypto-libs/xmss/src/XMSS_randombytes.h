#ifndef XMSS_RANDOMBYTES_H
#define XMSS_RANDOMBYTES_H

/* Fills x with cryptographic random bytes from the platform CSPRNG. */
void randombytes(unsigned char *x, unsigned long long xlen);

#endif /* XMSS_RANDOMBYTES_H */
