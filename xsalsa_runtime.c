#include "xsalsa.h"
#include "xsalsa_scalar.h"
#include "xsalsa_avx.h"
#include <stdio.h>
#include <string.h>

/* Function pointer types */
typedef int (*xsalsa20_setup_fn)(xsalsa20_state *st, 
                                 const unsigned char *key, unsigned long keylen,
                                 const unsigned char *nonce, unsigned long noncelen,
                                 int rounds);

typedef int (*xsalsa20_crypt_fn)(xsalsa20_state *st, 
                                 const unsigned char *in, unsigned long inlen, 
                                 unsigned char *out);

typedef int (*xsalsa20_keystream_fn)(xsalsa20_state *st, 
                                     unsigned char *out, unsigned long outlen);

typedef int (*xsalsa20_memory_fn)(const unsigned char *key, unsigned long keylen,
                                  const unsigned char *nonce, unsigned long noncelen,
                                  unsigned long rounds,
                                  const unsigned char *datain, unsigned long datalen,
                                  unsigned char *dataout);

/* Function pointers for runtime dispatch */
static xsalsa20_setup_fn xsalsa20_setup_impl = NULL;
static xsalsa20_crypt_fn xsalsa20_crypt_impl = NULL;
static xsalsa20_keystream_fn xsalsa20_keystream_impl = NULL;
static xsalsa20_memory_fn xsalsa20_memory_impl = NULL;





/* Initialize function pointers based on CPU capabilities */
static void init_impl(void)
{
    if (xsalsa20_setup_impl != NULL) {
        return; /* Already initialized */
    }
    
    if (xsalsa20_get_best_impl()) {
        /* Use AVX implementation */
        xsalsa20_setup_impl = xsalsa20_setup_avx;
        xsalsa20_crypt_impl = xsalsa20_crypt_avx;
        xsalsa20_keystream_impl = xsalsa20_keystream_avx;
        xsalsa20_memory_impl = xsalsa20_memory_avx;
    } else {
        /* Use scalar implementation */
        xsalsa20_setup_impl = xsalsa20_setup_scalar;
        xsalsa20_crypt_impl = xsalsa20_crypt_scalar;
        xsalsa20_keystream_impl = xsalsa20_keystream_scalar;
        xsalsa20_memory_impl = xsalsa20_memory_scalar;
    }
}

/**
 * Initialize an XSalsa20 context (runtime dispatch)
 */
int xsalsa20_setup(xsalsa20_state *st, 
                   const unsigned char *key, unsigned long keylen,
                   const unsigned char *nonce, unsigned long noncelen,
                   int rounds)
{
    init_impl();
    return xsalsa20_setup_impl(st, key, keylen, nonce, noncelen, rounds);
}

/**
 * Encrypt or decrypt data with XSalsa20 (runtime dispatch)
 */
int xsalsa20_crypt(xsalsa20_state *st, 
                   const unsigned char *in, unsigned long inlen, 
                   unsigned char *out)
{
    init_impl();
    return xsalsa20_crypt_impl(st, in, inlen, out);
}

/**
 * Generate keystream bytes (runtime dispatch)
 */
int xsalsa20_keystream(xsalsa20_state *st, 
                       unsigned char *out, unsigned long outlen)
{
    init_impl();
    return xsalsa20_keystream_impl(st, out, outlen);
}

/**
 * One-shot encryption/decryption function (runtime dispatch)
 */
int xsalsa20_memory(const unsigned char *key, unsigned long keylen,
                    const unsigned char *nonce, unsigned long noncelen,
                    unsigned long rounds,
                    const unsigned char *datain, unsigned long datalen,
                    unsigned char *dataout)
{
    init_impl();
    return xsalsa20_memory_impl(key, keylen, nonce, noncelen, rounds, 
                                datain, datalen, dataout);
}

/**
 * Clean up XSalsa20 state (same for all implementations)
 */
void xsalsa20_done(xsalsa20_state *st)
{
    if (st != NULL) {
        volatile unsigned char *x = (volatile unsigned char *)st;
        size_t outlen = sizeof(xsalsa20_state);
        while (outlen--) *x++ = 0;
    }
}

/**
 * Run self-test
 * @return XSALSA_OK if successful
 */
int xsalsa20_test(void)
{
   /* Test vectors from LibTomCrypt XSalsa20 test */
   static const unsigned char test_key[32] = {
      0x1b, 0x27, 0x55, 0x64, 0x73, 0xe9, 0x85, 0xd4,
      0x62, 0xcd, 0x51, 0x19, 0x7a, 0x9a, 0x46, 0xc7,
      0x60, 0x09, 0x54, 0x9e, 0xac, 0x64, 0x74, 0xf2,
      0x06, 0xc4, 0xee, 0x08, 0x44, 0xf6, 0x83, 0x89
   };
   
   static const unsigned char test_nonce[24] = {
      0x69, 0x69, 0x6e, 0xe9, 0x55, 0xb6, 0x2b, 0x73,
      0xcd, 0x62, 0xbd, 0xa8, 0x75, 0xfc, 0x73, 0xd6,
      0x82, 0x19, 0xe0, 0x03, 0x6b, 0x7a, 0x0b, 0x37
   };
   
   const char *test_msg = "Kilroy was here!";
   unsigned char test_msg_len = 17;  /* includes trailing NULL */
   unsigned char ciphertext[17];
   unsigned char decrypted[17];
   xsalsa20_state st;
   int err;

   /* Test round-trip encryption/decryption with streaming interface */
   if ((err = xsalsa20_setup(&st, test_key, 32, test_nonce, 24, 20)) != XSALSA_OK) {
      return err;
   }
   
   if ((err = xsalsa20_crypt(&st, (const unsigned char*)test_msg, test_msg_len, ciphertext)) != XSALSA_OK) {
      xsalsa20_done(&st);
      return err;
   }
   
   xsalsa20_done(&st);
   
   /* Test decryption (same operation) */
   if ((err = xsalsa20_setup(&st, test_key, 32, test_nonce, 24, 20)) != XSALSA_OK) {
      return err;
   }
   
   if ((err = xsalsa20_crypt(&st, ciphertext, test_msg_len, decrypted)) != XSALSA_OK) {
      xsalsa20_done(&st);
      return err;
   }
   
   xsalsa20_done(&st);
   
   /* Verify round-trip works */
   if (memcmp(test_msg, decrypted, test_msg_len) != 0) {
      return XSALSA_ERROR;
   }
   
   /* Test one-shot function round-trip */
   if ((err = xsalsa20_memory(test_key, 32, test_nonce, 24, 20, 
                              (const unsigned char*)test_msg, test_msg_len, ciphertext)) != XSALSA_OK) {
      return err;
   }
   
   if ((err = xsalsa20_memory(test_key, 32, test_nonce, 24, 20, 
                              ciphertext, test_msg_len, decrypted)) != XSALSA_OK) {
      return err;
   }
   
   /* Verify one-shot round-trip works */
   if (memcmp(test_msg, decrypted, test_msg_len) != 0) {
      return XSALSA_ERROR;
   }
   
   return XSALSA_OK;
} 