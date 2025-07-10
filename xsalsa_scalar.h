#ifndef XSALSA_SCALAR_H
#define XSALSA_SCALAR_H

#include "xsalsa.h"

#ifdef __cplusplus
extern "C" {
#endif


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

inline void xsalsa20_scalar_init(xsalsa20_setup_fn *xsalsa20_setup_impl, xsalsa20_crypt_fn *xsalsa20_crypt_impl, xsalsa20_keystream_fn *xsalsa20_keystream_impl, xsalsa20_memory_fn *xsalsa20_memory_impl) {
    #ifdef XSALSA_USE_IMPL_SCALAR
    *xsalsa20_setup_impl = xsalsa20_setup_scalar;
    *xsalsa20_crypt_impl = xsalsa20_crypt_scalar;
    *xsalsa20_keystream_impl = xsalsa20_keystream_scalar;
    *xsalsa20_memory_impl = xsalsa20_memory_scalar;
    #endif
}

#ifdef __cplusplus
}
#endif

#endif /* XSALSA_SCALAR_H */