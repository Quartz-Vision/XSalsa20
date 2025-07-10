#ifndef XSALSA_AVX512_H
#define XSALSA_AVX512_H

#include "xsalsa.h"


int xsalsa20_setup_avx512(xsalsa20_state *st, const unsigned char *key, unsigned long keylen,
                                         const unsigned char *nonce, unsigned long noncelen,
                                         int rounds);
int xsalsa20_crypt_avx512(xsalsa20_state *st, const unsigned char *in, unsigned long inlen, unsigned char *out);
int xsalsa20_keystream_avx512(xsalsa20_state *st, unsigned char *out, unsigned long outlen);
int xsalsa20_memory_avx512(const unsigned char *key, unsigned long keylen,
                       const unsigned char *nonce, unsigned long noncelen,
                       unsigned long rounds,
                       const unsigned char *datain, unsigned long datalen,
                       unsigned char *dataout);

static inline void xsalsa20_avx512_init(xsalsa20_setup_fn *xsalsa20_setup_impl, xsalsa20_crypt_fn *xsalsa20_crypt_impl, xsalsa20_keystream_fn *xsalsa20_keystream_impl, xsalsa20_memory_fn *xsalsa20_memory_impl) {
    #ifdef XSALSA_USE_IMPL_AVX512
    *xsalsa20_setup_impl = xsalsa20_setup_avx512;
    *xsalsa20_crypt_impl = xsalsa20_crypt_avx512;
    *xsalsa20_keystream_impl = xsalsa20_keystream_avx512;
    *xsalsa20_memory_impl = xsalsa20_memory_avx512;
    #endif
}


#endif /* XSALSA_AVX512_H */ 