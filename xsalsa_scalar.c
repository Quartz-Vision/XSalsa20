#ifdef XSALSA_USE_IMPL_SCALAR

#include "xsalsa.h"
#include <string.h>

/* Internal macros and definitions */
#define XSALSA_ARGCHK(x) do { if (!(x)) return XSALSA_INVALID_ARG; } while(0)

/* Endianness detection and macros */
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__ || \
    defined(__LITTLE_ENDIAN__) || defined(__ARMEL__) || defined(__THUMBEL__) || \
    defined(__AARCH64EL__) || defined(_MIPSEL) || defined(__MIPSEL) || \
    defined(__MIPSEL__) || defined(_M_ARM) || defined(_M_ARM64) || \
    defined(__i386__) || defined(__x86_64__) || defined(_M_IX86) || defined(_M_X64)
    #define ENDIAN_LITTLE
#elif defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__ || \
      defined(__BIG_ENDIAN__) || defined(__ARMEB__) || defined(__THUMBEB__) || \
      defined(__AARCH64EB__) || defined(_MIPSEB) || defined(__MIPSEB) || \
      defined(__MIPSEB__) || defined(__sparc__) || defined(__sparc)
    #define ENDIAN_BIG
#else
    #define ENDIAN_LITTLE  /* Default to little endian */
#endif

/* Byte order macros */
#ifdef ENDIAN_LITTLE
    #define STORE32L(x, y) do { \
        (y)[0] = (unsigned char)((x)&255); \
        (y)[1] = (unsigned char)(((x)>>8)&255); \
        (y)[2] = (unsigned char)(((x)>>16)&255); \
        (y)[3] = (unsigned char)(((x)>>24)&255); \
    } while(0)
    
    #define LOAD32L(x, y) do { \
        x = ((ulong32)((y)[0] & 255)) | \
            ((ulong32)((y)[1] & 255) << 8) | \
            ((ulong32)((y)[2] & 255) << 16) | \
            ((ulong32)((y)[3] & 255) << 24); \
    } while(0)
#else
    #define STORE32L(x, y) do { \
        (y)[3] = (unsigned char)((x)&255); \
        (y)[2] = (unsigned char)(((x)>>8)&255); \
        (y)[1] = (unsigned char)(((x)>>16)&255); \
        (y)[0] = (unsigned char)(((x)>>24)&255); \
    } while(0)
    
    #define LOAD32L(x, y) do { \
        x = ((ulong32)((y)[3] & 255)) | \
            ((ulong32)((y)[2] & 255) << 8) | \
            ((ulong32)((y)[1] & 255) << 16) | \
            ((ulong32)((y)[0] & 255) << 24); \
    } while(0)
#endif

/* Rotate left macro */
#define ROL(x, y) (((x) << (y)) | ((x) >> (32 - (y))))

/* Quarter round macro */
#define QUARTERROUND(a,b,c,d) \
    x[b] ^= (ROL((x[a] + x[d]),  7)); \
    x[c] ^= (ROL((x[b] + x[a]),  9)); \
    x[d] ^= (ROL((x[c] + x[b]), 13)); \
    x[a] ^= (ROL((x[d] + x[c]), 18));

/* Constants */
static const char * const constants = "expand 32-byte k";

/* Internal function: XSalsa20 doubleround (no final addition as in Salsa20) */
static void s_xsalsa20_doubleround(ulong32 *x, int rounds)
{
   int i;

   for (i = rounds; i > 0; i -= 2) {
      /* columnround */
      QUARTERROUND( 0, 4, 8,12)
      QUARTERROUND( 5, 9,13, 1)
      QUARTERROUND(10,14, 2, 6)
      QUARTERROUND(15, 3, 7,11)
      /* rowround */
      QUARTERROUND( 0, 1, 2, 3)
      QUARTERROUND( 5, 6, 7, 4)
      QUARTERROUND(10,11, 8, 9)
      QUARTERROUND(15,12,13,14)
   }
}

/* Internal function: Salsa20 block generation */
static void s_salsa20_block(unsigned char *output, const ulong32 *input, int rounds)
{
   ulong32 x[16];
   int i;
   memcpy(x, input, sizeof(x));
   
   for (i = rounds; i > 0; i -= 2) {
      QUARTERROUND( 0, 4, 8,12)
      QUARTERROUND( 5, 9,13, 1)
      QUARTERROUND(10,14, 2, 6)
      QUARTERROUND(15, 3, 7,11)
      QUARTERROUND( 0, 1, 2, 3)
      QUARTERROUND( 5, 6, 7, 4)
      QUARTERROUND(10,11, 8, 9)
      QUARTERROUND(15,12,13,14)
   }
   
   for (i = 0; i < 16; ++i) {
     x[i] += input[i];
     STORE32L(x[i], output + 4 * i);
   }
}

/* Internal function: Zero memory */
static void zeromem(volatile void *out, size_t outlen)
{
   volatile unsigned char *x = (volatile unsigned char *)out;
   while (outlen--) *x++ = 0;
}

/* Internal function: Minimum macro */
#define MIN(a, b) ((a) < (b) ? (a) : (b))

/**
   Initialize an XSalsa20 context
   @param st        [out] The destination of the XSalsa20 state
   @param key       The secret key
   @param keylen    The length of the secret key, must be 32 (octets)
   @param nonce     The nonce
   @param noncelen  The length of the nonce, must be 24 (octets)
   @param rounds    Number of rounds (must be evenly divisible by 2, default is 20)
   @return XSALSA_OK if successful
*/
int xsalsa20_setup_scalar(xsalsa20_state *st, const unsigned char *key, unsigned long keylen,
                                      const unsigned char *nonce, unsigned long noncelen,
                                      int rounds)
{
   const int sti[] = {0, 5, 10, 15, 6, 7, 8, 9};  /* indices used to build subkey fm x */
   ulong32       x[64];                           /* input to & output fm doubleround */
   unsigned char subkey[32];
   int i;

   XSALSA_ARGCHK(st        != NULL);
   XSALSA_ARGCHK(key       != NULL);
   XSALSA_ARGCHK(keylen    == 32);
   XSALSA_ARGCHK(nonce     != NULL);
   XSALSA_ARGCHK(noncelen  == 24);
   if (rounds == 0) rounds = 20;
   XSALSA_ARGCHK(rounds % 2 == 0);     /* number of rounds must be evenly divisible by 2 */

   /* load the state to "hash" the key */
   LOAD32L(x[ 0], constants +  0);
   LOAD32L(x[ 5], constants +  4);
   LOAD32L(x[10], constants +  8);
   LOAD32L(x[15], constants + 12);
   LOAD32L(x[ 1], key +  0);
   LOAD32L(x[ 2], key +  4);
   LOAD32L(x[ 3], key +  8);
   LOAD32L(x[ 4], key + 12);
   LOAD32L(x[11], key + 16);
   LOAD32L(x[12], key + 20);
   LOAD32L(x[13], key + 24);
   LOAD32L(x[14], key + 28);
   LOAD32L(x[ 6], nonce +  0);
   LOAD32L(x[ 7], nonce +  4);
   LOAD32L(x[ 8], nonce +  8);
   LOAD32L(x[ 9], nonce + 12);

   /* use modified salsa20 doubleround (no final addition) */
   s_xsalsa20_doubleround(x, rounds);

   /* extract the subkey */
   for (i = 0; i < 8; ++i) {
     STORE32L(x[sti[i]], subkey + 4 * i);
   }

   /* load the final initial state */
   LOAD32L(st->input[ 0], constants +  0);
   LOAD32L(st->input[ 5], constants +  4);
   LOAD32L(st->input[10], constants +  8);
   LOAD32L(st->input[15], constants + 12);
   LOAD32L(st->input[ 1], subkey +  0);
   LOAD32L(st->input[ 2], subkey +  4);
   LOAD32L(st->input[ 3], subkey +  8);
   LOAD32L(st->input[ 4], subkey + 12);
   LOAD32L(st->input[11], subkey + 16);
   LOAD32L(st->input[12], subkey + 20);
   LOAD32L(st->input[13], subkey + 24);
   LOAD32L(st->input[14], subkey + 28);
   LOAD32L(st->input[ 6], &(nonce[16]) + 0);
   LOAD32L(st->input[ 7], &(nonce[16]) + 4);
   st->input[ 8] = 0;
   st->input[ 9] = 0;
   st->rounds = rounds;
   st->ksleft = 0;
   st->ivlen  = 24;           /* set switch to say nonce/IV has been loaded */

   zeromem(x, sizeof(x));
   zeromem(subkey, sizeof(subkey));

   return XSALSA_OK;
}

/**
   Encrypt (or decrypt) bytes of ciphertext (or plaintext) with XSalsa20
   @param st      The XSalsa20 state
   @param in      The plaintext (or ciphertext)
   @param inlen   The length of the input (octets)
   @param out     [out] The ciphertext (or plaintext), length inlen
   @return XSALSA_OK if successful
*/
int xsalsa20_crypt_scalar(xsalsa20_state *st, const unsigned char *in, unsigned long inlen, unsigned char *out)
{
   unsigned char buf[64];
   unsigned long i, j;

   if (inlen == 0) return XSALSA_OK; /* nothing to do */

   XSALSA_ARGCHK(st        != NULL);
   XSALSA_ARGCHK(in        != NULL);
   XSALSA_ARGCHK(out       != NULL);
   XSALSA_ARGCHK(st->ivlen == 24);

   if (st->ksleft > 0) {
      j = MIN(st->ksleft, inlen);
      for (i = 0; i < j; ++i, st->ksleft--) out[i] = in[i] ^ st->kstream[64 - st->ksleft];
      inlen -= j;
      if (inlen == 0) return XSALSA_OK;
      out += j;
      in  += j;
   }
   for (;;) {
     s_salsa20_block(buf, st->input, st->rounds);
     /* XSalsa20: 64-bit counter, increment 64-bit counter */
     if (0 == ++st->input[8] && 0 == ++st->input[9]) return XSALSA_OVERFLOW;
     if (inlen <= 64) {
       for (i = 0; i < inlen; ++i) out[i] = in[i] ^ buf[i];
       st->ksleft = 64 - inlen;
       for (i = inlen; i < 64; ++i) st->kstream[i] = buf[i];
       return XSALSA_OK;
     }
     for (i = 0; i < 64; ++i) out[i] = in[i] ^ buf[i];
     inlen -= 64;
     out += 64;
     in  += 64;
   }
}

/**
   Generate keystream bytes
   @param st      The XSalsa20 state
   @param out     [out] The keystream output
   @param outlen  The number of keystream bytes to generate
   @return XSALSA_OK if successful
*/
int xsalsa20_keystream_scalar(xsalsa20_state *st, unsigned char *out, unsigned long outlen)
{
   unsigned char buf[64];
   unsigned long i, j;

   if (outlen == 0) return XSALSA_OK; /* nothing to do */

   XSALSA_ARGCHK(st        != NULL);
   XSALSA_ARGCHK(out       != NULL);
   XSALSA_ARGCHK(st->ivlen == 24);

   if (st->ksleft > 0) {
      j = MIN(st->ksleft, outlen);
      for (i = 0; i < j; ++i, st->ksleft--) out[i] = st->kstream[64 - st->ksleft];
      outlen -= j;
      if (outlen == 0) return XSALSA_OK;
      out += j;
   }
   for (;;) {
     s_salsa20_block(buf, st->input, st->rounds);
     /* XSalsa20: 64-bit counter, increment 64-bit counter */
     if (0 == ++st->input[8] && 0 == ++st->input[9]) return XSALSA_OVERFLOW;
     if (outlen <= 64) {
       for (i = 0; i < outlen; ++i) out[i] = buf[i];
       st->ksleft = 64 - outlen;
       for (i = outlen; i < 64; ++i) st->kstream[i] = buf[i];
       return XSALSA_OK;
     }
     for (i = 0; i < 64; ++i) out[i] = buf[i];
     outlen -= 64;
     out += 64;
   }
}



/**
   One-shot encryption/decryption function
   @param key       The secret key (32 bytes)
   @param keylen    The length of the secret key (must be 32)
   @param nonce     The nonce (24 bytes)
   @param noncelen  The length of the nonce (must be 24)
   @param rounds    Number of rounds (must be evenly divisible by 2, default is 20)
   @param datain    The input data
   @param datalen   The length of the input data
   @param dataout   [out] The output data (same length as input)
   @return XSALSA_OK if successful
*/
int xsalsa20_memory_scalar(const unsigned char *key, unsigned long keylen,
                    const unsigned char *nonce, unsigned long noncelen,
                    unsigned long rounds,
                    const unsigned char *datain, unsigned long datalen,
                    unsigned char *dataout)
{
   xsalsa20_state st;
   int err;

   XSALSA_ARGCHK(key       != NULL);
   XSALSA_ARGCHK(nonce     != NULL);
   XSALSA_ARGCHK(datain    != NULL);
   XSALSA_ARGCHK(dataout   != NULL);

   if ((err = xsalsa20_setup_scalar(&st, key, keylen, nonce, noncelen, (int)rounds)) != XSALSA_OK) {
      return err;
   }
   if ((err = xsalsa20_crypt_scalar(&st, datain, datalen, dataout)) != XSALSA_OK) {
      xsalsa20_done(&st);
      return err;
   }
   xsalsa20_done(&st);
   return XSALSA_OK;
}

#endif /* IMPL_SCALAR */