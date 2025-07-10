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

/* AVX-512 quarter round macro - processes 16 words at once */
#define QUARTERROUND_AVX512(a,b,c,d) \
    x[b] = _mm512_xor_si512(x[b], _mm512_or_si512( \
        _mm512_slli_epi32(_mm512_add_epi32(x[a], x[d]), 7), \
        _mm512_srli_epi32(_mm512_add_epi32(x[a], x[d]), 25))); \
    x[c] = _mm512_xor_si512(x[c], _mm512_or_si512( \
        _mm512_slli_epi32(_mm512_add_epi32(x[b], x[a]), 9), \
        _mm512_srli_epi32(_mm512_add_epi32(x[b], x[a]), 23))); \
    x[d] = _mm512_xor_si512(x[d], _mm512_or_si512( \
        _mm512_slli_epi32(_mm512_add_epi32(x[c], x[b]), 13), \
        _mm512_srli_epi32(_mm512_add_epi32(x[c], x[b]), 19))); \
    x[a] = _mm512_xor_si512(x[a], _mm512_or_si512( \
        _mm512_slli_epi32(_mm512_add_epi32(x[d], x[c]), 18), \
        _mm512_srli_epi32(_mm512_add_epi32(x[d], x[c]), 14)));

/* Constants */
static const char * const constants = "expand 32-byte k";

/* Internal function: XSalsa20 doubleround with AVX-512 (no final addition as in Salsa20) */
void s_xsalsa20_doubleround_avx512(ulong32 *x, int rounds)
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

/* Internal function: Salsa20 block generation with AVX-512 */
void s_salsa20_block_avx512(unsigned char *output, const ulong32 *input, int rounds)
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
   
   /* Use AVX-512 for the final addition and store */
   for (i = 0; i < 16; i += 16) {
      __m512i input_vec = _mm512_set_epi32(
         input[i+15], input[i+14], input[i+13], input[i+12],
         input[i+11], input[i+10], input[i+9], input[i+8],
         input[i+7], input[i+6], input[i+5], input[i+4],
         input[i+3], input[i+2], input[i+1], input[i]
      );
      __m512i state_vec = _mm512_set_epi32(
         x[i+15], x[i+14], x[i+13], x[i+12],
         x[i+11], x[i+10], x[i+9], x[i+8],
         x[i+7], x[i+6], x[i+5], x[i+4],
         x[i+3], x[i+2], x[i+1], x[i]
      );
      __m512i sum_vec = _mm512_add_epi32(state_vec, input_vec);
      _mm512_storeu_si512((__m512i*)(output + 4 * i), sum_vec);
   }
}

/* Internal function: Zero memory */
void zeromem(volatile void *out, size_t outlen)
{
   volatile unsigned char *x = (volatile unsigned char *)out;
   while (outlen--) *x++ = 0;
}

#define MIN(a, b) ((a) < (b) ? (a) : (b))

/* AVX-512 vectorized quarter round - processes 16 blocks in parallel */
void quarterround_avx512_16blocks(__m512i *x, int a, int b, int c, int d)
{
   __m512i temp;
   
   /* x[b] ^= ROL((x[a] + x[d]), 7) */
   temp = _mm512_add_epi32(x[a], x[d]);
   x[b] = _mm512_xor_si512(x[b], _mm512_or_si512(
      _mm512_slli_epi32(temp, 7),
      _mm512_srli_epi32(temp, 25)
   ));
   
   /* x[c] ^= ROL((x[b] + x[a]), 9) */
   temp = _mm512_add_epi32(x[b], x[a]);
   x[c] = _mm512_xor_si512(x[c], _mm512_or_si512(
      _mm512_slli_epi32(temp, 9),
      _mm512_srli_epi32(temp, 23)
   ));
   
   /* x[d] ^= ROL((x[c] + x[b]), 13) */
   temp = _mm512_add_epi32(x[c], x[b]);
   x[d] = _mm512_xor_si512(x[d], _mm512_or_si512(
      _mm512_slli_epi32(temp, 13),
      _mm512_srli_epi32(temp, 19)
   ));
   
   /* x[a] ^= ROL((x[d] + x[c]), 18) */
   temp = _mm512_add_epi32(x[d], x[c]);
   x[a] = _mm512_xor_si512(x[a], _mm512_or_si512(
      _mm512_slli_epi32(temp, 18),
      _mm512_srli_epi32(temp, 14)
   ));
}

/* AVX-512 vectorized Salsa20 block generation - processes 16 blocks at once */
void s_salsa20_block_avx512_16blocks(unsigned char *output, const ulong32 *input, int rounds)
{
   __m512i x[16];  /* 16 __m512i = 256 32-bit values (16 blocks) */
   int i, j;
   
   /* Load 16 blocks into AVX-512 vectors */
   for (i = 0; i < 16; i++) {
      for (j = 0; j < 16; j++) {
         x[i] = _mm512_set_epi32(
            input[i*16 + j*4 + 3], input[i*16 + j*4 + 2],
            input[i*16 + j*4 + 1], input[i*16 + j*4 + 0],
            input[i*16 + (j+1)*4 + 3], input[i*16 + (j+1)*4 + 2],
            input[i*16 + (j+1)*4 + 1], input[i*16 + (j+1)*4 + 0],
            input[i*16 + (j+2)*4 + 3], input[i*16 + (j+2)*4 + 2],
            input[i*16 + (j+2)*4 + 1], input[i*16 + (j+2)*4 + 0],
            input[i*16 + (j+3)*4 + 3], input[i*16 + (j+3)*4 + 2],
            input[i*16 + (j+3)*4 + 1], input[i*16 + (j+3)*4 + 0]
         );
      }
   }
   
   /* Process rounds */
   for (i = rounds; i > 0; i -= 2) {
      /* columnround */
      quarterround_avx512_16blocks(x,  0,  4,  8, 12);
      quarterround_avx512_16blocks(x,  5,  9, 13,  1);
      quarterround_avx512_16blocks(x, 10, 14,  2,  6);
      quarterround_avx512_16blocks(x, 15,  3,  7, 11);
      /* rowround */
      quarterround_avx512_16blocks(x,  0,  1,  2,  3);
      quarterround_avx512_16blocks(x,  5,  6,  7,  4);
      quarterround_avx512_16blocks(x, 10, 11,  8,  9);
      quarterround_avx512_16blocks(x, 15, 12, 13, 14);
   }
   
   /* Store results */
   for (i = 0; i < 16; i++) {
      for (j = 0; j < 16; j++) {
         _mm512_storeu_si512((__m512i*)(output + (i*16 + j*4) * 4), x[i]);
      }
   }
}

/**
   Initialize an XSalsa20 context (AVX-512 version)
   @param st        [out] The destination of the XSalsa20 state
   @param key       The secret key
   @param keylen    The length of the secret key, must be 32 (octets)
   @param nonce     The nonce
   @param noncelen  The length of the nonce, must be 24 (octets)
   @param rounds    Number of rounds (must be evenly divisible by 2, default is 20)
   @return XSALSA_OK if successful
*/
int xsalsa20_setup_avx512(xsalsa20_state *st, const unsigned char *key, unsigned long keylen,
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
   s_xsalsa20_doubleround_avx512(x, rounds);

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

   /* Use AVX-512 for zeroing memory */
   for (i = 0; i < 64; i += 64) {
      _mm512_storeu_si512((__m512i*)(x + i), _mm512_setzero_si512());
   }
   for (i = 0; i < 32; i += 32) {
      _mm512_storeu_si512((__m512i*)(subkey + i), _mm512_setzero_si512());
   }

   return XSALSA_OK;
}

/**
   Encrypt (or decrypt) bytes of ciphertext (or plaintext) with XSalsa20 (AVX-512 version)
   @param st      The XSalsa20 state
   @param in      The plaintext (or ciphertext)
   @param inlen   The length of the input (octets)
   @param out     [out] The ciphertext (or plaintext), length inlen
   @return XSALSA_OK if successful
*/
int xsalsa20_crypt_avx512(xsalsa20_state *st, const unsigned char *in, unsigned long inlen, unsigned char *out)
{
   unsigned char buf[1024];  /* Buffer for 16 blocks (16 * 64 = 1024 bytes) */
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
   
   /* Process data in 16-block chunks for better AVX-512 utilization */
   while (inlen >= 1024) {
      /* Generate 16 blocks of keystream */
      ulong32 input_blocks[256];  /* 16 blocks * 16 words each */
      int block;
      
      /* Prepare 16 blocks with consecutive counters */
      for (block = 0; block < 16; block++) {
         for (i = 0; i < 16; i++) {
            input_blocks[block * 16 + i] = st->input[i];
         }
         /* Increment counter for next block */
         if (block < 15) {
            input_blocks[block * 16 + 8]++;
            if (input_blocks[block * 16 + 8] == 0) {
               input_blocks[block * 16 + 9]++;
            }
         }
      }
      
      /* Generate keystream for all 16 blocks at once */
      s_salsa20_block_avx512_16blocks(buf, input_blocks, st->rounds);
      
      /* XOR with input using AVX-512 */
      for (i = 0; i < 1024; i += 64) {
         __m512i in_vec = _mm512_loadu_si512((__m512i*)(in + i));
         __m512i buf_vec = _mm512_loadu_si512((__m512i*)(buf + i));
         __m512i out_vec = _mm512_xor_si512(in_vec, buf_vec);
         _mm512_storeu_si512((__m512i*)(out + i), out_vec);
      }
      
      /* Update counter for next iteration */
      st->input[8] += 16;
      if (st->input[8] < 16) {  /* Overflow check */
         st->input[9]++;
         if (st->input[9] == 0) return XSALSA_OVERFLOW;
      }
      
      inlen -= 1024;
      out += 1024;
      in  += 1024;
   }
   
   /* Handle remaining data with single blocks */
   for (;;) {
     s_salsa20_block_avx512(buf, st->input, st->rounds);
     /* XSalsa20: 64-bit counter, increment 64-bit counter */
     if (0 == ++st->input[8] && 0 == ++st->input[9]) return XSALSA_OVERFLOW;
     if (inlen <= 64) {
       /* Use AVX-512 for XOR operations when possible */
       if (inlen >= 64) {
          __m512i in_vec = _mm512_loadu_si512((__m512i*)(in));
          __m512i buf_vec = _mm512_loadu_si512((__m512i*)(buf));
          __m512i out_vec = _mm512_xor_si512(in_vec, buf_vec);
          _mm512_storeu_si512((__m512i*)(out), out_vec);
       } else {
          for (i = 0; i < inlen; ++i) out[i] = in[i] ^ buf[i];
       }
       st->ksleft = 64 - inlen;
       for (i = inlen; i < 64; ++i) st->kstream[i] = buf[i];
       return XSALSA_OK;
     }
     /* Use AVX-512 for XOR operations */
     for (i = 0; i < 64; i += 64) {
        __m512i in_vec = _mm512_loadu_si512((__m512i*)(in + i));
        __m512i buf_vec = _mm512_loadu_si512((__m512i*)(buf + i));
        __m512i out_vec = _mm512_xor_si512(in_vec, buf_vec);
        _mm512_storeu_si512((__m512i*)(out + i), out_vec);
     }
     inlen -= 64;
     out += 64;
     in  += 64;
   }
}

/**
   Generate keystream bytes (AVX-512 version)
   @param st      The XSalsa20 state
   @param out     [out] The keystream output
   @param outlen  The number of keystream bytes to generate
   @return XSALSA_OK if successful
*/
int xsalsa20_keystream_avx512(xsalsa20_state *st, unsigned char *out, unsigned long outlen)
{
   unsigned char buf[1024];  /* Buffer for 16 blocks (16 * 64 = 1024 bytes) */
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
   
   /* Process data in 16-block chunks for better AVX-512 utilization */
   while (outlen >= 1024) {
      /* Generate 16 blocks of keystream */
      ulong32 input_blocks[256];  /* 16 blocks * 16 words each */
      int block;
      
      /* Prepare 16 blocks with consecutive counters */
      for (block = 0; block < 16; block++) {
         for (i = 0; i < 16; i++) {
            input_blocks[block * 16 + i] = st->input[i];
         }
         /* Increment counter for next block */
         if (block < 15) {
            input_blocks[block * 16 + 8]++;
            if (input_blocks[block * 16 + 8] == 0) {
               input_blocks[block * 16 + 9]++;
            }
         }
      }
      
      /* Generate keystream for all 16 blocks at once */
      s_salsa20_block_avx512_16blocks(buf, input_blocks, st->rounds);
      
      /* Copy keystream using AVX-512 */
      for (i = 0; i < 1024; i += 64) {
         __m512i buf_vec = _mm512_loadu_si512((__m512i*)(buf + i));
         _mm512_storeu_si512((__m512i*)(out + i), buf_vec);
      }
      
      /* Update counter for next iteration */
      st->input[8] += 16;
      if (st->input[8] < 16) {  /* Overflow check */
         st->input[9]++;
         if (st->input[9] == 0) return XSALSA_OVERFLOW;
      }
      
      outlen -= 1024;
      out += 1024;
   }
   
   /* Handle remaining data with single blocks */
   for (;;) {
     s_salsa20_block_avx512(buf, st->input, st->rounds);
     /* XSalsa20: 64-bit counter, increment 64-bit counter */
     if (0 == ++st->input[8] && 0 == ++st->input[9]) return XSALSA_OVERFLOW;
     if (outlen <= 64) {
       /* Use AVX-512 for memory copy when possible */
       if (outlen >= 64) {
          __m512i buf_vec = _mm512_loadu_si512((__m512i*)(buf));
          _mm512_storeu_si512((__m512i*)(out), buf_vec);
       } else {
          for (i = 0; i < outlen; ++i) out[i] = buf[i];
       }
       st->ksleft = 64 - outlen;
       for (i = outlen; i < 64; ++i) st->kstream[i] = buf[i];
       return XSALSA_OK;
     }
     /* Use AVX-512 for memory copy */
     for (i = 0; i < 64; i += 64) {
        __m512i buf_vec = _mm512_loadu_si512((__m512i*)(buf + i));
        _mm512_storeu_si512((__m512i*)(out + i), buf_vec);
     }
     outlen -= 64;
     out += 64;
   }
}

/**
   One-shot encryption/decryption function (AVX-512 version)
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
int xsalsa20_memory_avx512(const unsigned char *key, unsigned long keylen,
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

   if ((err = xsalsa20_setup_avx512(&st, key, keylen, nonce, noncelen, (int)rounds)) != XSALSA_OK) {
      return err;
   }
   if ((err = xsalsa20_crypt_avx512(&st, datain, datalen, dataout)) != XSALSA_OK) {
      xsalsa20_done(&st);
      return err;
   }
   xsalsa20_done(&st);
   return XSALSA_OK;
} 