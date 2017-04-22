#include <string.h>
#include <stdint.h>
#include "sph_sha1.h"
#include "sph_sha2.h"
#include "hash.h"
#include "hash_simd.h"

#ifdef NTRU_DETECT_SIMD
uint32_t OPENSSL_ia32cap_P[] __attribute__((visibility("hidden"))) = {0, 0, 0, 0};
#else
#ifdef __AVX2__
/* don’t detect SHA extensions for now, just report AVX/AVX2 */
uint32_t OPENSSL_ia32cap_P[] __attribute__((visibility("hidden"))) = {0, 1<<28, 1<<5, 0};
#else
uint32_t OPENSSL_ia32cap_P[] __attribute__((visibility("hidden"))) = {0, 0, 0, 0};
#endif
#endif   /* NTRU_DETECT_SIMD */

void (*ntru_sha1_4way_ptr)(uint8_t *input[4], uint16_t input_len, uint8_t *digest[4]);

void (*ntru_sha256_4way_ptr)(uint8_t *input[4], uint16_t input_len, uint8_t *digest[4]);

void (*ntru_sha1_8way_ptr)(uint8_t *input[4], uint16_t input_len, uint8_t *digest[4]);

void (*ntru_sha256_8way_ptr)(uint8_t *input[8], uint16_t input_len, uint8_t *digest[8]);

inline void ntru_sha1_4way(uint8_t *input[4], uint16_t input_len, uint8_t *digest[4]) {
    ntru_sha1_4way_ptr(input, input_len, digest);
}

void ntru_sha256_4way(uint8_t *input[4], uint16_t input_len, uint8_t *digest[4]) {
    ntru_sha256_4way_ptr(input, input_len, digest);
}

inline void ntru_sha1_8way(uint8_t *input[8], uint16_t input_len, uint8_t *digest[8]) {
    ntru_sha1_8way_ptr(input, input_len, digest);
}

void ntru_sha256_8way(uint8_t *input[8], uint16_t input_len, uint8_t *digest[8]) {
    ntru_sha256_8way_ptr(input, input_len, digest);
}

void ntru_sha1(uint8_t *input, uint16_t input_len, uint8_t *digest) {
    sph_sha1_context context;
    sph_sha1_init(&context);
    sph_sha1(&context, input, input_len);
    sph_sha1_close(&context, digest);
}

void ntru_sha256(uint8_t *input, uint16_t input_len, uint8_t *digest) {
    sph_sha256_context context;
    sph_sha256_init(&context);
    sph_sha256(&context, input, input_len);
    sph_sha256_close(&context, digest);
}

void ntru_sha1_4way_nosimd(uint8_t *input[4], uint16_t input_len, uint8_t *digest[4]) {
    uint8_t i;
    for (i=0; i<4; i++)
        ntru_sha1(input[i], input_len, digest[i]);
}

void ntru_sha1_8way_nosimd(uint8_t *input[8], uint16_t input_len, uint8_t *digest[8]) {
    uint8_t i;
    for (i=0; i<8; i++)
        ntru_sha1(input[i], input_len, digest[i]);
}

void ntru_sha256_4way_nosimd(uint8_t *input[4], uint16_t input_len, uint8_t *digest[4]) {
    uint8_t i;
    for (i=0; i<4; i++)
        ntru_sha256(input[i], input_len, digest[i]);
}

void ntru_sha256_8way_nosimd(uint8_t *input[8], uint16_t input_len, uint8_t *digest[8]) {
    uint8_t i;
    for (i=0; i<8; i++)
        ntru_sha256(input[i], input_len, digest[i]);
}

void ntru_set_optimized_impl_hash() {
#ifdef NTRU_DETECT_SIMD
    if (__builtin_cpu_supports("ssse3") || __builtin_cpu_supports("avx2")) {
        ntru_sha1_4way_ptr = ntru_sha1_4way_simd;
        ntru_sha256_4way_ptr = ntru_sha256_4way_simd;
        ntru_sha1_8way_ptr = ntru_sha1_8way_simd;
        ntru_sha256_8way_ptr = ntru_sha256_8way_simd;
        if (__builtin_cpu_supports("avx2")) {
            OPENSSL_ia32cap_P[1] = 1<<28;
            OPENSSL_ia32cap_P[2] = 1<<5;
        }
    }
    else {
        ntru_sha1_4way_ptr = ntru_sha1_4way_nosimd;
        ntru_sha256_4way_ptr = ntru_sha256_4way_nosimd;
        ntru_sha1_8way_ptr = ntru_sha1_8way_nosimd;
        ntru_sha256_8way_ptr = ntru_sha256_8way_nosimd;
    }
#else
#if defined __SSSE3__ || __AVX2__
    ntru_sha1_4way_ptr = ntru_sha1_4way_simd;
    ntru_sha256_4way_ptr = ntru_sha256_4way_simd;
    ntru_sha1_8way_ptr = ntru_sha1_8way_simd;
    ntru_sha256_8way_ptr = ntru_sha256_8way_simd;
#ifdef __AVX2__
    OPENSSL_ia32cap_P[1] = 1<<28;
    OPENSSL_ia32cap_P[2] = 1<<5;
#endif
#else
    ntru_sha1_4way_ptr = ntru_sha1_4way_nosimd;
    ntru_sha256_4way_ptr = ntru_sha256_4way_nosimd;
    ntru_sha1_8way_ptr = ntru_sha1_8way_nosimd;
    ntru_sha256_8way_ptr = ntru_sha256_8way_nosimd;
#endif   /*  __SSSE3__ || __AVX2__ */
#endif   /* NTRU_DETECT_SIMD */
}
