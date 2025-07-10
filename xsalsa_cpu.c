#include "xsalsa.h"
#include <stdint.h>

/* CPU feature detection */
static int impl_selected = -1;  /* -1 = not checked */

#ifdef XSALSA_ARCH_X86
#include <cpuid.h>

/**
 * Check if CPU supports AVX
 * @return 1 if AVX is supported, 0 otherwise
 */
static int check_avx_support(void)
{
    int cpu_has_avx = -1;
    unsigned int eax, ebx, ecx, edx;
    
    /* Check if CPUID supports leaf 1 */
    if (__get_cpuid(1, &eax, &ebx, &ecx, &edx) == 0) {
        cpu_has_avx = 0;
        return 0;
    }
    
    /* Check for AVX support (bit 28 in ecx) */
    if (ecx & (1 << 28)) {
        cpu_has_avx = 1;
    } else {
        cpu_has_avx = 0;
    }
    
    return cpu_has_avx;
}
#endif

/**
 * Get the best available implementation
 * @return 1 for AVX, 0 for scalar
 */
int xsalsa20_get_best_impl(void)
{
    #ifdef XSALSA_USE_IMPL_AVX
    if (impl_selected != -1) {
        return impl_selected;
    }

    impl_selected = check_avx_support();
    return impl_selected;
    #else
    return XSALSA_IMPL_SCALAR;
    #endif
}

/**
 * Force a specific implementation (for testing)
 * @param impl 0 for scalar, 1 for AVX
 */
void xsalsa20_force_impl(int impl)
{
    impl_selected = impl;
} 