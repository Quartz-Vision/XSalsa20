#ifndef XSALSA_H
#define XSALSA_H

#include <stdint.h>
#include <stddef.h>

/* Error codes */
#define XSALSA_OK 0
#define XSALSA_ERROR -1
#define XSALSA_INVALID_ARG -2
#define XSALSA_INVALID_KEYSIZE -3
#define XSALSA_INVALID_NONCE_SIZE -4
#define XSALSA_INVALID_ROUNDS -5
#define XSALSA_OVERFLOW -6

#define XSALSA_IMPL_SCALAR 0
#define XSALSA_IMPL_AVX 1
#define XSALSA_IMPL_AVX2 2
#define XSALSA_IMPL_AVX512 3

/* Data types */
typedef uint32_t ulong32;
typedef uint64_t ulong64;

/* XSalsa20 state structure */
typedef struct {
    ulong32 input[16];        /* The input state */
    unsigned char kstream[64]; /* Keystream buffer */
    unsigned long ksleft;      /* Number of keystream bytes left */
    unsigned long ivlen;       /* Length of IV/nonce */
    int rounds;               /* Number of rounds */
} xsalsa20_state;


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


/**
 * Initialize an XSalsa20 context
 * @param st        [out] The destination of the XSalsa20 state
 * @param key       The secret key (must be 32 bytes)
 * @param keylen    The length of the secret key (must be 32)
 * @param nonce     The nonce (must be 24 bytes)
 * @param noncelen  The length of the nonce (must be 24)
 * @param rounds    Number of rounds (must be evenly divisible by 2, default is 20)
 * @return XSALSA_OK if successful
 */
int xsalsa20_setup(xsalsa20_state *st, 
                   const unsigned char *key, unsigned long keylen,
                   const unsigned char *nonce, unsigned long noncelen,
                   int rounds);

/**
 * Encrypt or decrypt data with XSalsa20
 * @param st      The XSalsa20 state (must be initialized with xsalsa20_setup)
 * @param in      The input data
 * @param inlen   The length of the input data
 * @param out     [out] The output data (same length as input)
 * @return XSALSA_OK if successful
 */
int xsalsa20_crypt(xsalsa20_state *st, 
                   const unsigned char *in, unsigned long inlen, 
                   unsigned char *out);

/**
 * Generate keystream bytes
 * @param st      The XSalsa20 state (must be initialized with xsalsa20_setup)
 * @param out     [out] The keystream output
 * @param outlen  The number of keystream bytes to generate
 * @return XSALSA_OK if successful
 */
int xsalsa20_keystream(xsalsa20_state *st, 
                       unsigned char *out, unsigned long outlen);

/**
 * Clean up XSalsa20 state
 * @param st      The XSalsa20 state to clean up
 */
void xsalsa20_done(xsalsa20_state *st);

/**
 * One-shot encryption/decryption function
 * @param key       The secret key (32 bytes)
 * @param keylen    The length of the secret key (must be 32)
 * @param nonce     The nonce (24 bytes)
 * @param noncelen  The length of the nonce (must be 24)
 * @param rounds    Number of rounds (must be evenly divisible by 2, default is 20)
 * @param datain    The input data
 * @param datalen   The length of the input data
 * @param dataout   [out] The output data (same length as input)
 * @return XSALSA_OK if successful
 */
int xsalsa20_memory(const unsigned char *key, unsigned long keylen,
                    const unsigned char *nonce, unsigned long noncelen,
                    unsigned long rounds,
                    const unsigned char *datain, unsigned long datalen,
                    unsigned char *dataout);

/**
 * Reset the last selected implementation
 */
void xsalsa20_reset_impl(void);

/**
 * Run self-test
 * @return XSALSA_OK if successful
 */
int xsalsa20_test(void);
#endif /* XSALSA_H */ 