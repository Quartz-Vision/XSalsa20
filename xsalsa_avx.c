#ifdef XSALSA_USE_IMPL_AVX

#include "xsalsa.h"
#include <immintrin.h>
#include <string.h>
#include <stdio.h>


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

/* AVX quarter round macro - processes 4 words at once */
#define QUARTERROUND_AVX(a,b,c,d) \
    x[b] = _mm_xor_si128(x[b], _mm_or_si128( \
        _mm_slli_epi32(_mm_add_epi32(x[a], x[d]), 7), \
        _mm_srli_epi32(_mm_add_epi32(x[a], x[d]), 25))); \
    x[c] = _mm_xor_si128(x[c], _mm_or_si128( \
        _mm_slli_epi32(_mm_add_epi32(x[b], x[a]), 9), \
        _mm_srli_epi32(_mm_add_epi32(x[b], x[a]), 23))); \
    x[d] = _mm_xor_si128(x[d], _mm_or_si128( \
        _mm_slli_epi32(_mm_add_epi32(x[c], x[b]), 13), \
        _mm_srli_epi32(_mm_add_epi32(x[c], x[b]), 19))); \
    x[a] = _mm_xor_si128(x[a], _mm_or_si128( \
        _mm_slli_epi32(_mm_add_epi32(x[d], x[c]), 18), \
        _mm_srli_epi32(_mm_add_epi32(x[d], x[c]), 14)));

/* Constants */
static const char * const constants = "expand 32-byte k";

/* Internal function: XSalsa20 doubleround with AVX (no final addition as in Salsa20) */
static void s_xsalsa20_doubleround_avx(ulong32 *x, int rounds)
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

/* Internal function: Salsa20 block generation with AVX */
static void s_salsa20_block_avx(unsigned char *output, const ulong32 *input, int rounds)
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
   
   /* Use AVX for the final addition and store */
   for (i = 0; i < 16; i += 4) {
      __m128i input_vec = _mm_set_epi32(input[i+3], input[i+2], input[i+1], input[i]);
      __m128i state_vec = _mm_set_epi32(x[i+3], x[i+2], x[i+1], x[i]);
      __m128i sum_vec = _mm_add_epi32(state_vec, input_vec);
      _mm_storeu_si128((__m128i*)(output + 4 * i), sum_vec);
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

/* AVX vectorized quarter round - processes 4 blocks in parallel */
static void quarterround_avx_4blocks(__m128i *x, int a, int b, int c, int d)
{
   __m128i temp;
   
   /* x[b] ^= ROL((x[a] + x[d]), 7) */
   temp = _mm_add_epi32(x[a], x[d]);
   x[b] = _mm_xor_si128(x[b], _mm_or_si128(
      _mm_slli_epi32(temp, 7),
      _mm_srli_epi32(temp, 25)
   ));
   
   /* x[c] ^= ROL((x[b] + x[a]), 9) */
   temp = _mm_add_epi32(x[b], x[a]);
   x[c] = _mm_xor_si128(x[c], _mm_or_si128(
      _mm_slli_epi32(temp, 9),
      _mm_srli_epi32(temp, 23)
   ));
   
   /* x[d] ^= ROL((x[c] + x[b]), 13) */
   temp = _mm_add_epi32(x[c], x[b]);
   x[d] = _mm_xor_si128(x[d], _mm_or_si128(
      _mm_slli_epi32(temp, 13),
      _mm_srli_epi32(temp, 19)
   ));
   
   /* x[a] ^= ROL((x[d] + x[c]), 18) */
   temp = _mm_add_epi32(x[d], x[c]);
   x[a] = _mm_xor_si128(x[a], _mm_or_si128(
      _mm_slli_epi32(temp, 18),
      _mm_srli_epi32(temp, 14)
   ));
}

/* AVX vectorized Salsa20 block generation - processes 4 blocks at once */
static void s_salsa20_block_avx_4blocks(unsigned char *output, const ulong32 *input, int rounds)
{
   __m128i x[16];  /* 16 __m128i = 64 32-bit values (4 blocks) */
   int i, j;
   
   /* Load 4 blocks into AVX vectors */
   for (i = 0; i < 16; i += 4) {
      for (j = 0; j < 4; j++) {
         x[i+j] = _mm_set_epi32(
            input[i*4 + j*4 + 3], input[i*4 + j*4 + 2],
            input[i*4 + j*4 + 1], input[i*4 + j*4 + 0]
         );
      }
   }
   
   /* Process rounds */
   for (i = rounds; i > 0; i -= 2) {
      /* columnround */
      quarterround_avx_4blocks(x,  0,  4,  8, 12);
      quarterround_avx_4blocks(x,  5,  9, 13,  1);
      quarterround_avx_4blocks(x, 10, 14,  2,  6);
      quarterround_avx_4blocks(x, 15,  3,  7, 11);
      /* rowround */
      quarterround_avx_4blocks(x,  0,  1,  2,  3);
      quarterround_avx_4blocks(x,  5,  6,  7,  4);
      quarterround_avx_4blocks(x, 10, 11,  8,  9);
      quarterround_avx_4blocks(x, 15, 12, 13, 14);
   }
   
   /* Store results */
   for (i = 0; i < 16; i += 4) {
      for (j = 0; j < 4; j++) {
         _mm_storeu_si128((__m128i*)(output + (i*4 + j*4) * 4), x[i+j]);
      }
   }
}



/**
   Initialize an XSalsa20 context (AVX version)
   @param st        [out] The destination of the XSalsa20 state
   @param key       The secret key
   @param keylen    The length of the secret key, must be 32 (octets)
   @param nonce     The nonce
   @param noncelen  The length of the nonce, must be 24 (octets)
   @param rounds    Number of rounds (must be evenly divisible by 2, default is 20)
   @return XSALSA_OK if successful
*/
int xsalsa20_setup_avx(xsalsa20_state *st, const unsigned char *key, unsigned long keylen,
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
   s_xsalsa20_doubleround_avx(x, rounds);

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

   /* Use AVX for zeroing memory */
   for (i = 0; i < 64; i += 16) {
      _mm_storeu_si128((__m128i*)(x + i), _mm_setzero_si128());
   }
   for (i = 0; i < 32; i += 16) {
      _mm_storeu_si128((__m128i*)(subkey + i), _mm_setzero_si128());
   }

   return XSALSA_OK;
}

/**
   Encrypt (or decrypt) bytes of ciphertext (or plaintext) with XSalsa20 (AVX version)
   @param st      The XSalsa20 state
   @param in      The plaintext (or ciphertext)
   @param inlen   The length of the input (octets)
   @param out     [out] The ciphertext (or plaintext), length inlen
   @return XSALSA_OK if successful
*/
int xsalsa20_crypt_avx(xsalsa20_state *st, const unsigned char *in, unsigned long inlen, unsigned char *out)
{
   unsigned char buf[256];  /* Buffer for 4 blocks (4 * 64 = 256 bytes) */
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
   
   /* Process data in 4-block chunks for better AVX utilization */
   while (inlen >= 256) {
      /* Generate 4 blocks of keystream */
      ulong32 input_blocks[64];  /* 4 blocks * 16 words each */
      int block;
      
      /* Prepare 4 blocks with consecutive counters */
      for (block = 0; block < 4; block++) {
         for (i = 0; i < 16; i++) {
            input_blocks[block * 16 + i] = st->input[i];
         }
         /* Increment counter for next block */
         if (block < 3) {
            input_blocks[block * 16 + 8]++;
            if (input_blocks[block * 16 + 8] == 0) {
               input_blocks[block * 16 + 9]++;
            }
         }
      }
      
      /* Generate keystream for all 4 blocks at once */
      s_salsa20_block_avx_4blocks(buf, input_blocks, st->rounds);
      
      /* XOR with input using AVX */
      for (i = 0; i < 256; i += 16) {
         __m128i in_vec = _mm_loadu_si128((__m128i*)(in + i));
         __m128i buf_vec = _mm_loadu_si128((__m128i*)(buf + i));
         __m128i out_vec = _mm_xor_si128(in_vec, buf_vec);
         _mm_storeu_si128((__m128i*)(out + i), out_vec);
      }
      
      /* Update counter for next iteration */
      st->input[8] += 4;
      if (st->input[8] < 4) {  /* Overflow check */
         st->input[9]++;
         if (st->input[9] == 0) return XSALSA_OVERFLOW;
      }
      
      inlen -= 256;
      out += 256;
      in  += 256;
   }
   
   /* Handle remaining data with single blocks */
   for (;;) {
     s_salsa20_block_avx(buf, st->input, st->rounds);
     /* XSalsa20: 64-bit counter, increment 64-bit counter */
     if (0 == ++st->input[8] && 0 == ++st->input[9]) return XSALSA_OVERFLOW;
     if (inlen <= 64) {
       /* Use AVX for XOR operations when possible */
       if (inlen >= 16) {
          for (i = 0; i < inlen - 15; i += 16) {
             __m128i in_vec = _mm_loadu_si128((__m128i*)(in + i));
             __m128i buf_vec = _mm_loadu_si128((__m128i*)(buf + i));
             __m128i out_vec = _mm_xor_si128(in_vec, buf_vec);
             _mm_storeu_si128((__m128i*)(out + i), out_vec);
          }
          /* Handle remaining bytes */
          for (; i < inlen; ++i) out[i] = in[i] ^ buf[i];
       } else {
          for (i = 0; i < inlen; ++i) out[i] = in[i] ^ buf[i];
       }
       st->ksleft = 64 - inlen;
       for (i = inlen; i < 64; ++i) st->kstream[i] = buf[i];
       return XSALSA_OK;
     }
     /* Use AVX for XOR operations */
     for (i = 0; i < 64; i += 16) {
        __m128i in_vec = _mm_loadu_si128((__m128i*)(in + i));
        __m128i buf_vec = _mm_loadu_si128((__m128i*)(buf + i));
        __m128i out_vec = _mm_xor_si128(in_vec, buf_vec);
        _mm_storeu_si128((__m128i*)(out + i), out_vec);
     }
     inlen -= 64;
     out += 64;
     in  += 64;
   }
}

/**
   Generate keystream bytes (AVX version)
   @param st      The XSalsa20 state
   @param out     [out] The keystream output
   @param outlen  The number of keystream bytes to generate
   @return XSALSA_OK if successful
*/
int xsalsa20_keystream_avx(xsalsa20_state *st, unsigned char *out, unsigned long outlen)
{
   unsigned char buf[256];  /* Buffer for 4 blocks (4 * 64 = 256 bytes) */
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
   
   /* Process data in 4-block chunks for better AVX utilization */
   while (outlen >= 256) {
      /* Generate 4 blocks of keystream */
      ulong32 input_blocks[64];  /* 4 blocks * 16 words each */
      int block;
      
      /* Prepare 4 blocks with consecutive counters */
      for (block = 0; block < 4; block++) {
         for (i = 0; i < 16; i++) {
            input_blocks[block * 16 + i] = st->input[i];
         }
         /* Increment counter for next block */
         if (block < 3) {
            input_blocks[block * 16 + 8]++;
            if (input_blocks[block * 16 + 8] == 0) {
               input_blocks[block * 16 + 9]++;
            }
         }
      }
      
      /* Generate keystream for all 4 blocks at once */
      s_salsa20_block_avx_4blocks(buf, input_blocks, st->rounds);
      
      /* Copy keystream using AVX */
      for (i = 0; i < 256; i += 16) {
         __m128i buf_vec = _mm_loadu_si128((__m128i*)(buf + i));
         _mm_storeu_si128((__m128i*)(out + i), buf_vec);
      }
      
      /* Update counter for next iteration */
      st->input[8] += 4;
      if (st->input[8] < 4) {  /* Overflow check */
         st->input[9]++;
         if (st->input[9] == 0) return XSALSA_OVERFLOW;
      }
      
      outlen -= 256;
      out += 256;
   }
   
   /* Handle remaining data with single blocks */
   for (;;) {
     s_salsa20_block_avx(buf, st->input, st->rounds);
     /* XSalsa20: 64-bit counter, increment 64-bit counter */
     if (0 == ++st->input[8] && 0 == ++st->input[9]) return XSALSA_OVERFLOW;
     if (outlen <= 64) {
       /* Use AVX for memory copy when possible */
       if (outlen >= 16) {
          for (i = 0; i < outlen - 15; i += 16) {
             __m128i buf_vec = _mm_loadu_si128((__m128i*)(buf + i));
             _mm_storeu_si128((__m128i*)(out + i), buf_vec);
          }
          /* Handle remaining bytes */
          for (; i < outlen; ++i) out[i] = buf[i];
       } else {
          for (i = 0; i < outlen; ++i) out[i] = buf[i];
       }
       st->ksleft = 64 - outlen;
       for (i = outlen; i < 64; ++i) st->kstream[i] = buf[i];
       return XSALSA_OK;
     }
     /* Use AVX for memory copy */
     for (i = 0; i < 64; i += 16) {
        __m128i buf_vec = _mm_loadu_si128((__m128i*)(buf + i));
        _mm_storeu_si128((__m128i*)(out + i), buf_vec);
     }
     outlen -= 64;
     out += 64;
   }
}

/**
   One-shot encryption/decryption function (AVX version)
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
int xsalsa20_memory_avx(const unsigned char *key, unsigned long keylen,
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

   if ((err = xsalsa20_setup_avx(&st, key, keylen, nonce, noncelen, (int)rounds)) != XSALSA_OK) {
      return err;
   }
   if ((err = xsalsa20_crypt_avx(&st, datain, datalen, dataout)) != XSALSA_OK) {
      xsalsa20_done(&st);
      return err;
   }
   xsalsa20_done(&st);
   return XSALSA_OK;
} 

#endif /* IMPL_AVX */