#ifndef XSALSA_AVX_H
#define XSALSA_AVX_H

#include "xsalsa.h"

int xsalsa20_setup_avx(xsalsa20_state *st, const unsigned char *key, unsigned long keylen,
                                      const unsigned char *nonce, unsigned long noncelen,
                                      int rounds);
int xsalsa20_crypt_avx(xsalsa20_state *st, const unsigned char *in, unsigned long inlen, unsigned char *out);
int xsalsa20_keystream_avx(xsalsa20_state *st, unsigned char *out, unsigned long outlen);
int xsalsa20_memory_avx(const unsigned char *key, unsigned long keylen,
                    const unsigned char *nonce, unsigned long noncelen,
                    unsigned long rounds,
                    const unsigned char *datain, unsigned long datalen,
                    unsigned char *dataout);

#endif /* XSALSA_AVX_H */