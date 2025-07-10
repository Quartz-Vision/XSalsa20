#include "xsalsa.h"
#include <stdio.h>
#include <string.h>

static unsigned char key[32] = {
    0x1b, 0x27, 0x55, 0x64, 0x73, 0xe9, 0x85, 0xd4,
    0x62, 0xcd, 0x51, 0x19, 0x7a, 0x9a, 0x46, 0xc7,
    0x60, 0x09, 0x54, 0x9e, 0xac, 0x64, 0x74, 0xf2,
    0x06, 0xc4, 0xee, 0x08, 0x44, 0xf6, 0x83, 0x89
};

static unsigned char nonce[24] = {
    0x69, 0x69, 0x6e, 0xe9, 0x55, 0xb6, 0x2b, 0x73,
    0xcd, 0x62, 0xbd, 0xa8, 0x75, 0xfc, 0x73, 0xd6,
    0x82, 0x19, 0xe0, 0x03, 0x6b, 0x7a, 0x0b, 0x37
};

static const char *plaintext = "Hello, XSalsa20! This is a test message.";


int run_impl_tests(int impl)
{
    xsalsa20_force_impl(impl);

    /* Run the built-in test */
    if (xsalsa20_test() == XSALSA_OK) {
        printf("✓ Built-in test passed\n");
    } else {
        printf("✗ Built-in test failed\n");
        return 1;
    }
    
    unsigned long plaintext_len = strlen(plaintext);
    
    unsigned char encrypted[256];
    unsigned char decrypted[256];
    
    /* Test one-shot encryption */
    if (xsalsa20_memory(key, 32, nonce, 24, 20, 
                        (const unsigned char*)plaintext, plaintext_len, encrypted) == XSALSA_OK) {
        printf("✓ One-shot encryption successful\n");
    } else {
        printf("✗ One-shot encryption failed\n");
        return 1;
    }
    
    /* Test one-shot decryption (same operation) */
    if (xsalsa20_memory(key, 32, nonce, 24, 20, 
                        encrypted, plaintext_len, decrypted) == XSALSA_OK) {
        printf("✓ One-shot decryption successful\n");
    } else {
        printf("✗ One-shot decryption failed\n");
        return 1;
    }
    
    /* Verify decryption matches original */
    if (memcmp(plaintext, decrypted, plaintext_len) == 0) {
        printf("✓ Decryption matches original plaintext\n");
    } else {
        printf("✗ Decryption does not match original plaintext\n");
        return 1;
    }
    
    /* Test streaming interface */
    xsalsa20_state st;
    if (xsalsa20_setup(&st, key, 32, nonce, 24, 20) == XSALSA_OK) {
        printf("✓ Streaming setup successful\n");
    } else {
        printf("✗ Streaming setup failed\n");
        return 1;
    }
    
    if (xsalsa20_crypt(&st, (const unsigned char*)plaintext, plaintext_len, decrypted) == XSALSA_OK) {
        printf("✓ Streaming encryption successful\n");
    } else {
        printf("✗ Streaming encryption failed\n");
        xsalsa20_done(&st);
        return 1;
    }
    
    xsalsa20_done(&st);
    
    /* Verify streaming encryption matches one-shot */
    if (memcmp(encrypted, decrypted, plaintext_len) == 0) {
        printf("✓ Streaming encryption matches one-shot encryption\n");
    } else {
        printf("✗ Streaming encryption does not match one-shot encryption\n");
        return 1;
    }
    
    return 0;
}


int run_impl_comparison_tests(void)
{
    unsigned long plaintext_len = strlen(plaintext);
    unsigned char encrypted_scalar[256];
    unsigned char encrypted_avx[256];

    xsalsa20_force_impl(0);
    if (xsalsa20_memory(key, 32, nonce, 24, 20, 
                        (const unsigned char*)plaintext, plaintext_len, encrypted_scalar) != XSALSA_OK) {
        printf("✗ One-shot encryption failed (scalar)\n");
        return 1;
    }

    xsalsa20_force_impl(1);
    if (xsalsa20_memory(key, 32, nonce, 24, 20, 
                        (const unsigned char*)plaintext, plaintext_len, encrypted_avx) != XSALSA_OK) {
        printf("✗ One-shot encryption failed (avx)\n");
        return 1;
    }

    if (memcmp(encrypted_scalar, encrypted_avx, plaintext_len) == 0) {
        printf("✓ One-shot encryption matches\n");
    } else {
        printf("✗ One-shot encryption does not match\n");
        return 1;
    }
    return 0;
}


int main(void)
{
    int ret = 0;

    printf("Testing XSalsa20 SCALAR implementation...\n");
    if (run_impl_tests(0) != 0) {
        printf("✗ XSalsa20 SCALAR implementation failed\n");
        ret = 1;
    }

    printf("\nTesting XSalsa20 AVX implementation...\n");
    if (run_impl_tests(1) != 0) {
        printf("✗ XSalsa20 AVX implementation failed\n");
        ret = 1;
    }

    printf("\nTesting XSalsa20 implementation comparison...\n");
    if (run_impl_comparison_tests() != 0) {
        printf("✗ XSalsa20 implementation comparison failed\n");
        ret = 1;
    }

    if (ret == 0) {
        printf("All tests passed!\n");
    }
    
    return ret;
} 