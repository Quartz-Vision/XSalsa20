#include "xsalsa.h"
#include "xsalsa_impl_check.h"
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

typedef struct {
    const char *name;
    int impl;
    bool (*test_availability)(void);
} impl_test_t;

static const impl_test_t impls[] = {
    #ifdef XSALSA_USE_IMPL_SCALAR
    { "Scalar", XSALSA_IMPL_SCALAR, NULL },
    #else
    { "Scalar", -1, NULL },
    #endif

    #ifdef XSALSA_USE_IMPL_AVX
    { "AVX", XSALSA_IMPL_AVX, check_avx_support },
    #else
    { "AVX", -1, NULL },
    #endif

    #ifdef XSALSA_USE_IMPL_AVX2
    { "AVX2", XSALSA_IMPL_AVX2, check_avx2_support },
    #else
    { "AVX2", -1 },
    #endif

    #ifdef XSALSA_USE_IMPL_AVX512
    { "AVX512", XSALSA_IMPL_AVX512, check_avx512_support },
    #else
    { "AVX512", -1 },
    #endif
};


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
    unsigned char encrypted_prev[256];
    unsigned char encrypted_curr[256];
    int ret = 0;

    for (int i = 0; i < sizeof(impls) / sizeof(impls[0]); i++) {
        if (impls[i].impl == -1 || (impls[i].test_availability && !impls[i].test_availability())) {
            printf("Skipping XSalsa20 %s implementation (not available)\n", impls[i].name);
            continue;
        }

        xsalsa20_force_impl(impls[i].impl);

        if (xsalsa20_memory(key, 32, nonce, 24, 20, 
                            (const unsigned char*)plaintext, plaintext_len, encrypted_curr) != XSALSA_OK) {
            printf("✗ One-shot encryption failed for %s\n", impls[i].name);
            ret = 1;
        }

        if (i > 0 && memcmp(encrypted_prev, encrypted_curr, plaintext_len) != 0) {
            printf("✗ Not matching encrypted data, %s != %s\n", impls[i-1].name, impls[i].name);
            ret = 1;
        }
        memcpy(encrypted_prev, encrypted_curr, plaintext_len);
    }

    if (ret == 0) {
        printf("✓ All implementations match\n");
    }

    return ret;
}


int main(void)
{
    int ret = 0;

    for (int i = 0; i < sizeof(impls) / sizeof(impls[0]); i++) {
        if (impls[i].impl == -1 || (impls[i].test_availability && !impls[i].test_availability())) {
            printf("Skipping XSalsa20 %s implementation (not available)\n", impls[i].name);
            continue;
        }

        printf("\nTesting XSalsa20 %s implementation...\n", impls[i].name);
        if (run_impl_tests(impls[i].impl) != 0) {
            printf("✗ XSalsa20 %s implementation failed\n", impls[i].name);
            ret = 1;
        }
    }

    printf("\nTesting XSalsa20 implementations comparison...\n");
    if (run_impl_comparison_tests() != 0) {
        printf("✗ XSalsa20 implementations comparison failed\n");
        ret = 1;
    }

    if (ret == 0) {
        printf("All tests passed!\n");
    }
    
    return ret;
} 