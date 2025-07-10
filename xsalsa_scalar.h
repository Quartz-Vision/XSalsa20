#ifndef XSALSA_SCALAR_H
#define XSALSA_SCALAR_H

#include "xsalsa.h"

int xsalsa20_setup_scalar(xsalsa20_state *st, const unsigned char *key, unsigned long keylen,
                                      const unsigned char *nonce, unsigned long noncelen,
                                      int rounds);
int xsalsa20_crypt_scalar(xsalsa20_state *st, const unsigned char *in, unsigned long inlen, unsigned char *out);
int xsalsa20_keystream_scalar(xsalsa20_state *st, unsigned char *out, unsigned long outlen);
int xsalsa20_memory_scalar(const unsigned char *key, unsigned long keylen,
                    const unsigned char *nonce, unsigned long noncelen,
                    unsigned long rounds,
                    const unsigned char *datain, unsigned long datalen,
                    unsigned char *dataout);

#endif /* XSALSA_SCALAR_H */