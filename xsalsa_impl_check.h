#ifndef XSALSA_IMPL_CHECK_H
#define XSALSA_IMPL_CHECK_H

#include <stdint.h>
#include <stdbool.h>

bool check_avx_support(void);
bool check_avx2_support(void);
bool check_avx512_support(void);

/**
 * Get the best available implementation
 * @return 1 for AVX, 0 for scalar
 */
int xsalsa20_get_best_impl(void);

/**
 * Force a specific implementation (for testing)
 * @param impl 0 for scalar, 1 for AVX
 */
void xsalsa20_force_impl(int impl);

#endif /* XSALSA_IMPL_CHECK_H */