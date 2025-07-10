#include "xsalsa.h"
#include <stdbool.h>

/* CPU feature detection */
static volatile int impl_selected = -1;  /* -1 = not checked */

#ifdef XSALSA_ARCH_X86

#ifdef _WIN32
#include <intrin.h>

bool check_avx_support(void)
{
    int cpu_info[4];
    __cpuid(cpu_info, 1);
    /* ECX[28] - AVX flag */
    return (cpu_info[2] & (1 << 28));
}

bool check_avx2_support(void)
{
    int cpu_info[4];
    __cpuid(cpu_info, 7);
    /* EBX[5] - AVX2 flag */
    return (cpu_info[1] & (1 << 5));
}

bool check_avx512_support(void)
{
    int cpu_info[4];
    __cpuid(cpu_info, 7);
    /* EBX[16] - AVX-512F flag */
    return (cpu_info[1] & (1 << 16));
}
#else
#include <cpuid.h>

bool check_avx_support(void)
{
    unsigned int eax, ebx, ecx, edx;

    if (__get_cpuid(1, &eax, &ebx, &ecx, &edx) == 0) {
        return false;
    }

    /* ECX[28] - AVX flag */
    return (ecx & (1 << 28));
}

bool check_avx2_support(void)
{
    unsigned int eax, ebx, ecx, edx;
    
    /* Check if CPUID supports leaf 7 with subleaf 0 */
    if(__get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx) == 0) {
        return false;
    }
    
    /* EBX[5] - AVX2 flag */
    return (ebx & (1 << 5));
}

bool check_avx512_support(void)
{
    bool cpu_has_avx512 = false;
    unsigned int eax, ebx, ecx, edx;
   
    if (__get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx) == 0) {
        return false;
    }
    
    /* EBX[16] - AVX-512F flag */
    return (ebx & (1 << 16));
}
#endif /* _WIN32 */

#else /* XSALSA_ARCH_X86 */
bool check_avx_support(void)
{
    return false;
}

bool check_avx2_support(void)
{
    return false;
}

bool check_avx512_support(void)
{
    return false;
}
#endif /* XSALSA_ARCH_X86 */

int xsalsa20_get_best_impl(void)
{
    if (impl_selected != -1) {
        return impl_selected;
    }

    /* Check for best available implementation in order of preference */
    #ifdef XSALSA_USE_IMPL_AVX512
    if (check_avx512_support()) {
        impl_selected = XSALSA_IMPL_AVX512;
        return impl_selected;
    }
    #endif

    #ifdef XSALSA_USE_IMPL_AVX2
    if (check_avx2_support()) {
        impl_selected = XSALSA_IMPL_AVX2;
        return impl_selected;
    }
    #endif

    #ifdef XSALSA_USE_IMPL_AVX
    if (check_avx_support()) {
        impl_selected = XSALSA_IMPL_AVX;
        return impl_selected;
    }
    #endif

    impl_selected = XSALSA_IMPL_SCALAR;
    return impl_selected;
}

void xsalsa20_force_impl(int impl)
{
    impl_selected = impl;
    xsalsa20_reset_impl();
} 