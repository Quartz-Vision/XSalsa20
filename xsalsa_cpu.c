#include "xsalsa.h"
#include <cpuid.h>
#include <stdint.h>

/* CPU feature detection */
static int cpu_has_avx = -1;  /* -1 = not checked, 0 = no, 1 = yes */

/**
 * Check if CPU supports AVX
 * @return 1 if AVX is supported, 0 otherwise
 */
static int check_avx_support(void)
{
    if (cpu_has_avx != -1) {
        return cpu_has_avx;
    }
    
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

/**
 * Get the best available implementation
 * @return 1 for AVX, 0 for scalar
 */
int xsalsa20_get_best_impl(void)
{
    return check_avx_support();
}

/**
 * Force a specific implementation (for testing)
 * @param impl 0 for scalar, 1 for AVX
 */
void xsalsa20_force_impl(int impl)
{
    if (impl == 0) {
        cpu_has_avx = 0;
    } else if (impl == 1) {
        cpu_has_avx = 1;
    }
} 