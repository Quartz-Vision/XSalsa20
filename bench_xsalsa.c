#define _POSIX_C_SOURCE 200809L
#include "xsalsa.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define BENCH_SIZE_MB 100
#define BENCH_SECONDS 3

static void fill_random(unsigned char *buf, size_t len) {
    for (size_t i = 0; i < len; ++i)
        buf[i] = (unsigned char)(rand() & 0xFF);
}

static double timespec_to_sec(const struct timespec *start, const struct timespec *end) {
    return (end->tv_sec - start->tv_sec) + (end->tv_nsec - start->tv_nsec) / 1e9;
}

int main(void) {
    const size_t bufsize = BENCH_SIZE_MB * 1024 * 1024;
    unsigned char *key = malloc(32);
    unsigned char *nonce = malloc(24);
    unsigned char *inbuf = malloc(bufsize);
    unsigned char *outbuf = malloc(bufsize);
    if (!key || !nonce || !inbuf || !outbuf) {
        printf("Memory allocation failed\n");
        return 1;
    }
    fill_random(key, 32);
    fill_random(nonce, 24);
    fill_random(inbuf, bufsize);

    xsalsa20_state st;
    struct timespec t0, t1;
    size_t total_bytes = 0;
    double elapsed = 0.0;

    printf("XSalsa20 throughput benchmark\n");
    printf("Buffer size: %zu MB, Duration: %d seconds\n", (size_t)BENCH_SIZE_MB, BENCH_SECONDS);

    if (xsalsa20_setup(&st, key, 32, nonce, 24, 20) != XSALSA_OK) {
        printf("XSalsa20 setup failed\n");
        return 1;
    }

    clock_gettime(CLOCK_MONOTONIC, &t0);
    do {
        if (xsalsa20_crypt(&st, inbuf, bufsize, outbuf) != XSALSA_OK) {
            printf("XSalsa20 encrypt failed\n");
            return 1;
        }
        total_bytes += bufsize;
        clock_gettime(CLOCK_MONOTONIC, &t1);
        elapsed = timespec_to_sec(&t0, &t1);
    } while (elapsed < BENCH_SECONDS);
    xsalsa20_done(&st);

    double mb = total_bytes / (1024.0 * 1024.0);
    double mbps = mb / elapsed;
    printf("Total encrypted: %.2f MB in %.2f s\n", mb, elapsed);
    printf("Throughput: %.2f MB/s\n", mbps);

    free(key);
    free(nonce);
    free(inbuf);
    free(outbuf);
    return 0;
} 