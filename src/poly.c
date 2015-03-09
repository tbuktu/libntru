#include <stdlib.h>
#include <string.h>
#ifdef __SSSE3__
#include <tmmintrin.h>
#endif
#include "poly.h"
#include "rand.h"
#include "err.h"
#include "arith.h"

#ifdef __APPLE__
#include <libkern/OSByteOrder.h>
#define htole64(x) OSSwapHostToLittleInt64(x)
#endif
#ifdef __MINGW32__
/* assume little endian */
#define htole64(x) (x)
#endif

#define NTRU_SPARSE_THRESH 14

uint8_t ntru_num_bits(uint16_t n) {
    uint8_t b = 1;
    while (n >>= 1)
        b++;
    return b;
}

uint8_t ntru_rand_tern(uint16_t N, uint16_t num_ones, uint16_t num_neg_ones, NtruTernPoly *poly, NtruRandContext *rand_ctx) {
    int16_t coeffs[N];
    memset(&coeffs, 0, N * sizeof coeffs[0]);

    uint16_t rand_len = num_ones + num_neg_ones + 10;   /* 10 more to avoid calling the RNG again, for up to 10 collisions */
    uint16_t rand_data[rand_len*2];
    if (!rand_ctx->rand_gen->generate((uint8_t*)rand_data, rand_len*2, rand_ctx))
        return 0;
    uint16_t r_idx = 0;   /* index into rand_data */

    uint16_t bits = ntru_num_bits(N);
    uint16_t i = 0;
    while (i < num_ones) {
        uint16_t r = rand_data[r_idx] >> (8*sizeof r - bits);   /* 0 <= r < 2^bits */
        r_idx++;
        /* refill rand_data if we run out */
        if (r_idx >= rand_len) {
            if (!rand_ctx->rand_gen->generate((uint8_t*)rand_data, rand_len*2, rand_ctx))
                return 0;
            r_idx = 0;
        }
        if (r<N && !coeffs[r]) {
            poly->ones[i] = r;
            coeffs[r] = 1;
            i++;
        }
    }

    i = 0;
    while (i < num_neg_ones) {
        uint16_t r = rand_data[r_idx] >> (8*sizeof r - bits);   /* 0 <= r < 2^bits */
        r_idx++;
        /* refill rand_data if we run out */
        if (r_idx >= rand_len) {
            if (!rand_ctx->rand_gen->generate((uint8_t*)rand_data, rand_len*2, rand_ctx))
                return 0;
            r_idx = 0;
        }
        if (r<N && !coeffs[r]) {
            poly->neg_ones[i] = r;
            coeffs[r] = -1;
            i++;
        }
    }

    poly->N = N;
    poly->num_ones = num_ones;
    poly->num_neg_ones = num_neg_ones;

    return 1;
}

#ifndef NTRU_AVOID_HAMMING_WT_PATENT
uint8_t ntru_rand_prod(uint16_t N, uint16_t df1, uint16_t df2, uint16_t df3_ones, uint16_t df3_neg_ones, NtruProdPoly *poly, NtruRandContext *rand_ctx) {
    poly->N = N;
    uint8_t result = ntru_rand_tern(N, df1, df1, &poly->f1, rand_ctx);
    result &= ntru_rand_tern(N, df2, df2, &poly->f2, rand_ctx);
    result &= ntru_rand_tern(N, df3_ones, df3_neg_ones, &poly->f3, rand_ctx);
    return result;
}
#endif   /* NTRU_AVOID_HAMMING_WT_PATENT */

void ntru_add_tern(NtruIntPoly *a, NtruTernPoly *b) {
    uint16_t i;
    for (i=0; i<b->num_ones; i++)
        a->coeffs[b->ones[i]]++;
    for (i=0; i<b->num_neg_ones; i++)
        a->coeffs[b->neg_ones[i]]--;
}

void ntru_add_int(NtruIntPoly *a, NtruIntPoly *b) {
    uint16_t i;
    for (i=0; i<b->N; i++)
        a->coeffs[i] += b->coeffs[i];
}

void ntru_add_int_mod(NtruIntPoly *a, NtruIntPoly *b, uint16_t modulus) {
    uint16_t i;
    for (i=0; i<b->N; i++)
        a->coeffs[i] = (a->coeffs[i]+b->coeffs[i]) % modulus;
}

void ntru_add_int_mod2(NtruIntPoly *a, NtruIntPoly *b) {
    uint16_t i;
    for (i=0; i<b->N; i++)
        a->coeffs[i] = (a->coeffs[i]+b->coeffs[i]) & 1;
}

void ntru_add_int_mod2_64(uint64_t *a, uint64_t *b, uint16_t len) {
    uint16_t i;
    for (i=0; i<len; i++)
        a[i] ^= b[i];
}

void ntru_sub_int(NtruIntPoly *a, NtruIntPoly *b) {
    uint16_t i;
    for (i=0; i<b->N; i++)
        a->coeffs[i] -= b->coeffs[i];
}

void ntru_neg_mod(NtruIntPoly *a, uint16_t modulus) {
    uint16_t i;
    for (i=0; i<a->N; i++)
        a->coeffs[i] = modulus - a->coeffs[i];
}

uint8_t ntru_mult_int(NtruIntPoly *a, NtruIntPoly *b, NtruIntPoly *c, uint16_t modulus) {
#ifdef __SSSE3__
    return ntru_mult_int_sse(a, b, c, modulus);
#elif _LP64
    return ntru_mult_int_64(a, b, c, modulus);
#else
    return ntru_mult_int_16(a, b, c, modulus);
#endif
}

uint8_t ntru_mult_int_16(NtruIntPoly *a, NtruIntPoly *b, NtruIntPoly *c, uint16_t modulus) {
    uint16_t N = a->N;
    if (N != b->N)
        return 0;
    c->N = N;

    uint16_t k;
    for (k=0; k<N; k++) {
        int16_t ck = 0;
        uint16_t i;
        for (i=0; i<N; i++)
            ck += b->coeffs[i] * a->coeffs[(N+k-i)%N];
        c->coeffs[k] = ck % modulus;
    }

    return 1;
}

uint8_t ntru_mult_int_64(NtruIntPoly *a, NtruIntPoly *b, NtruIntPoly *c, uint16_t modulus) {
    uint16_t N = a->N;
    uint16_t N2 = (N+1) / 2;
    if (N != b->N)
        return 0;
    if (modulus & (modulus-1))   // check that modulus is a power of 2
        return 0;
    uint16_t mod_mask_16 = modulus - 1;
    uint64_t mod_mask_64 = mod_mask_16 + (mod_mask_16<<25);

    /* make 64-bit versions of a->coeffs and b->coeffs */
    uint64_t a_coeffs64[N2];
    uint64_t b_coeffs64[N2];
    uint16_t i;
    for (i=0; i<N/2; i++) {
        a_coeffs64[i] = (a->coeffs[2*i]&mod_mask_16) + (((uint64_t)(a->coeffs[2*i+1]&mod_mask_16))<<25);
        b_coeffs64[i] = (b->coeffs[2*i]&mod_mask_16) + (((uint64_t)(b->coeffs[2*i+1]&mod_mask_16))<<25);
    }
    if (N%2 == 1) {
        a_coeffs64[N2-1] = a->coeffs[N-1] & mod_mask_16;
        b_coeffs64[N2-1] = b->coeffs[N-1] & mod_mask_16;
    }

    /* multiply a_coeffs64 by b_coeffs64 */
    uint16_t clen = 2 * N2;   /* double capacity for intermediate result */
    uint64_t c_coeffs64[clen];
    memset(&c_coeffs64, 0, clen*8);
    uint16_t overflow_ctr_start = (1<<(25-ntru_log2(modulus))) - 1;
    uint16_t overflow_ctr_rem = overflow_ctr_start;
    for (i=0; i<N2; i++) {
        uint64_t j;
        for (j=0; j<N2; j++) {
            uint64_t ck = a_coeffs64[i] * b_coeffs64[j];
            c_coeffs64[i+j] += ck & mod_mask_64;
            c_coeffs64[i+j+1] += ck >> 50;
            overflow_ctr_rem--;
            if (!overflow_ctr_rem) {
                uint16_t k;
                for (k=0; k<clen; k++)
                    c_coeffs64[k] &= mod_mask_64;
                overflow_ctr_rem = overflow_ctr_start;
            }
        }
    }

    /* transform c_coeffs64 into NtruIntPoly representation */
    c->N = N;
    memset(&c->coeffs, 0, N*2);
    uint16_t k = 0;
    for (i=0; i<clen; i++) {
        c->coeffs[k] += c_coeffs64[i];
        if (++k >= N)
            k = 0;
        c->coeffs[k] += c_coeffs64[i] >> 25;
        if (++k >= N)
            k = 0;
    }

    /* take values mod modulus */
    for (i=0; i<N; i++)
        c->coeffs[i] &= mod_mask_16;

    return 1;
}

#ifdef __SSSE3__
uint8_t ntru_mult_int_sse(NtruIntPoly *a, NtruIntPoly *b, NtruIntPoly *c, uint16_t modulus) {
    uint16_t N = a->N;
    if (N != b->N)
        return 0;
    c->N = N;
    int16_t c_coeffs[2*NTRU_INT_POLY_SIZE];   /* double capacity for intermediate result */
    memset(&c_coeffs, 0, sizeof(c_coeffs));

    uint16_t k;
    for(k=N; k<NTRU_INT_POLY_SIZE; k++) {
        a->coeffs[k] = 0;
        b->coeffs[k] = 0;
    }
    for (k=0; k<N; k+=8) {
        uint8_t j;

        /* process coeffs in 8x8 blocks */
        __m128i b128[8];
        for (j=0; j<8; j++)
            b128[j] = _mm_set1_epi16(b->coeffs[k+j]);

        /* indices 0..7 */
        __m128i a128 = _mm_lddqu_si128((__m128i*)&a->coeffs[0]);
        __m128i c128 = _mm_lddqu_si128((__m128i*)&c_coeffs[k]);
        for (j=0; j<8; j++) {
            __m128i product = _mm_mullo_epi16(a128, b128[j]);
            c128 = _mm_add_epi16(c128, product);
            a128 = _mm_slli_si128(a128, 2);
        }
        _mm_storeu_si128((__m128i*)&c_coeffs[k], c128);

        /* indices 8... */
        uint16_t i;
        for (i=8; i<N+8; i+=8) {
            __m128i c128 = _mm_lddqu_si128((__m128i*)&c_coeffs[k+i]);
            __m128i a128_0 = _mm_lddqu_si128((__m128i*)&a->coeffs[i-7]);
            __m128i a128_1 = _mm_lddqu_si128((__m128i*)&a->coeffs[i]);
            for (j=0; j<8; j++) {
                __m128i product = _mm_mullo_epi16(a128_1, b128[j]);
                c128 = _mm_add_epi16(c128, product);

                a128_0 = _mm_slli_si128(a128_0, 2);
                a128_1 = _mm_alignr_epi8(a128_1, a128_0, 14);
            }
            _mm_storeu_si128((__m128i*)&c_coeffs[k+i], c128);
        }
    }
    /* no need to SSE-ify the following loop b/c the compiler auto-vectorizes it */
    for (k=0; k<N; k++)
        c->coeffs[k] = c_coeffs[k] + c_coeffs[N+k];

    ntru_mod(c, modulus);
    return 1;
}
#endif   /* __SSSE3__ */

uint8_t ntru_mult_tern(NtruIntPoly *a, NtruTernPoly *b, NtruIntPoly *c, uint16_t modulus) {
#ifdef __SSSE3__
    return ntru_mult_tern_sse(a, b, c, modulus);
#elif _LP64
    return ntru_mult_tern_64(a, b, c, modulus);
#else
    return ntru_mult_tern_16(a, b, c, modulus);
#endif
}

uint8_t ntru_mult_tern_16(NtruIntPoly *a, NtruTernPoly *b, NtruIntPoly *c, uint16_t modulus) {
    uint16_t N = a->N;
    if (N != b->N)
        return 0;
    c->N = N;
    memset(&c->coeffs, 0, N * sizeof c->coeffs[0]);

    uint16_t i;
    for (i=0; i<b->num_ones; i++) {
        int16_t j = N - 1 - b->ones[i];
        int16_t k;
        for(k=N-1; k>=0; k--) {
            c->coeffs[k] += a->coeffs[j];
            j--;
            if (j < 0)
                j = N - 1;
        }
    }

    for (i=0; i<b->num_neg_ones; i++) {
        int16_t j = N - 1 - b->neg_ones[i];
        int16_t k;
        for(k=N-1; k>=0; k--) {
            c->coeffs[k] -= a->coeffs[j];
            j--;
            if (j < 0)
                j = N - 1;
        }
    }

    ntru_mod(c, modulus);
    return 1;
}

uint8_t ntru_mult_tern_64(NtruIntPoly *a, NtruTernPoly *b, NtruIntPoly *c, uint16_t modulus) {
    uint16_t N = a->N;
    if (N != b->N)
        return 0;
    if (modulus & (modulus-1))   // check that modulus is a power of 2
        return 0;
    memset(&c->coeffs, 0, N * sizeof c->coeffs[0]);
    c->N = N;

    uint64_t mod_mask_64 = modulus - 1;
    mod_mask_64 += mod_mask_64 << 16;
    mod_mask_64 += mod_mask_64 << 32;
    typedef uint64_t __attribute__((__may_alias__)) uint64_t_alias;

    /* make sure a.coeffs[i] < modulus */
    ntru_mod(a, modulus);

    uint16_t overflow_ctr_start = (1<<16)/modulus - 1;
    uint16_t overflow_ctr_rem = overflow_ctr_start;

    /* add coefficients that are multiplied by 1 */
    uint16_t i;
    for (i=0; i<b->num_ones; i++) {
        int16_t j;
        int16_t k = b->ones[i];
        uint16_t j_end = N-4<b->ones[i] ? 0 : N-4-b->ones[i];
        for (j=0; j<j_end; j+=4,k+=4)
            *((uint64_t_alias*)&c->coeffs[k]) += *((uint64_t_alias*)&a->coeffs[j]);
        for (; k<N; k++,j++)
            c->coeffs[k] += a->coeffs[j];
        for (k=0; j<N-4; j+=4,k+=4)
            *((uint64_t_alias*)&c->coeffs[k]) += *((uint64_t_alias*)&a->coeffs[j]);
        for (; j<N; j++,k++)
            c->coeffs[k] += a->coeffs[j];

        overflow_ctr_rem--;
        if (!overflow_ctr_rem) {
            ntru_mod(c, modulus);
            overflow_ctr_rem = overflow_ctr_start;
        }
    }

    /* use inverse mask for subtraction */
    mod_mask_64 = ~mod_mask_64;
    for (i=0; i<N-4; i+=4)
        *((uint64_t_alias*)&c->coeffs[i]) |= mod_mask_64;
    for (; i<N; i++)
        c->coeffs[i] |= mod_mask_64;

    /* subtract coefficients that are multiplied by -1 */
    overflow_ctr_rem = overflow_ctr_start;
    for (i=0; i<b->num_neg_ones; i++) {
        int16_t j;
        int16_t k = b->neg_ones[i];
        uint16_t j_end = N-4<b->neg_ones[i] ? 0 : N-4-b->neg_ones[i];
        for (j=0; j<j_end; j+=4,k+=4)
            *((uint64_t_alias*)&c->coeffs[k]) -= *((uint64_t_alias*)&a->coeffs[j]);
        for (; k<N; k++,j++)
            c->coeffs[k] -= a->coeffs[j];
        for (k=0; j<N-4; j+=4,k+=4)
            *((uint64_t_alias*)&c->coeffs[k]) -= *((uint64_t_alias*)&a->coeffs[j]);
        for (; j<N; j++,k++)
            c->coeffs[k] -= a->coeffs[j];

        overflow_ctr_rem--;
        if (!overflow_ctr_rem) {
            for (j=0; j<N-4; j+=4)
                *((uint64_t_alias*)&c->coeffs[j]) |= mod_mask_64;
            for (; j<N; j++)
                c->coeffs[j] |= mod_mask_64;
            overflow_ctr_rem = overflow_ctr_start;
        }
    }

    c->N = N;
    ntru_mod(c, modulus);
    return 1;
}

#ifdef __SSSE3__
/* Optimized for small df */
uint8_t ntru_mult_tern_sse_sparse(NtruIntPoly *a, NtruTernPoly *b, NtruIntPoly *c, uint16_t modulus) {
    uint16_t N = a->N;
    if (N != b->N)
        return 0;
    if (modulus & (modulus-1))   // check that modulus is a power of 2
        return 0;
    memset(&c->coeffs, 0, N * sizeof c->coeffs[0]);
    c->N = N;

    /* add coefficients that are multiplied by 1 */
    uint16_t i;
    for (i=0; i<b->num_ones; i++) {
        int16_t j;
        int16_t k = b->ones[i];
        uint16_t j_end = N<b->ones[i] ? 0 : N-b->ones[i];
        /* it is safe not to truncate the last block of 8 coefficients */
        /* because there is extra room at the end of the coeffs array  */
        for (j=0; j<j_end; j+=8,k+=8) {
            __m128i ck = _mm_lddqu_si128((__m128i*)&c->coeffs[k]);
            __m128i aj = _mm_lddqu_si128((__m128i*)&a->coeffs[j]);
            __m128i ca = _mm_add_epi16(ck, aj);
            _mm_storeu_si128((__m128i*)&c->coeffs[k], ca);
        }
        j = j_end;
        for (k=0; j<N-7; j+=8,k+=8) {
            __m128i ck = _mm_lddqu_si128((__m128i*)&c->coeffs[k]);
            __m128i aj = _mm_lddqu_si128((__m128i*)&a->coeffs[j]);
            __m128i ca = _mm_add_epi16(ck, aj);
            _mm_storeu_si128((__m128i*)&c->coeffs[k], ca);
        }
        for (; j<N; j++,k++)
            c->coeffs[k] += a->coeffs[j];
    }

    /* subtract coefficients that are multiplied by -1 */
    for (i=0; i<b->num_neg_ones; i++) {
        int16_t j;
        int16_t k = b->neg_ones[i];
        uint16_t j_end = N<b->neg_ones[i] ? 0 : N-b->neg_ones[i];
        /* it is safe not to truncate the last block of 8 coefficients */
        /* because there is extra room at the end of the coeffs array  */
        for (j=0; j<j_end; j+=8,k+=8) {
            __m128i ck = _mm_lddqu_si128((__m128i*)&c->coeffs[k]);
            __m128i aj = _mm_lddqu_si128((__m128i*)&a->coeffs[j]);
            __m128i ca = _mm_sub_epi16(ck, aj);
            _mm_storeu_si128((__m128i*)&c->coeffs[k], ca);
        }
        j = j_end;
        for (k=0; j<N-7; j+=8,k+=8) {
            __m128i ck = _mm_lddqu_si128((__m128i*)&c->coeffs[k]);
            __m128i aj = _mm_lddqu_si128((__m128i*)&a->coeffs[j]);
            __m128i ca = _mm_sub_epi16(ck, aj);
            _mm_storeu_si128((__m128i*)&c->coeffs[k], ca);
        }
        for (; j<N; j++,k++)
            c->coeffs[k] -= a->coeffs[j];
    }

    c->N = N;
    ntru_mod(c, modulus);
    return 1;
}

/* Optimized for large df */
uint8_t ntru_mult_tern_sse_dense(NtruIntPoly *a, NtruTernPoly *b, NtruIntPoly *c, uint16_t modulus) {
    uint16_t N = a->N;
    if (N != b->N)
        return 0;
    if (modulus & (modulus-1))   // check that modulus is a power of 2
        return 0;
    c->N = N;

    uint16_t i;
    for(i=N; i<NTRU_INT_POLY_SIZE; i++)
        a->coeffs[i] = 0;
    int16_t c_coeffs_arr[8+2*NTRU_INT_POLY_SIZE];   /* double capacity for intermediate result + another 8 */
    int16_t *c_coeffs = c_coeffs_arr + 8;
    memset(&c_coeffs_arr, 0, sizeof(c_coeffs_arr));

    __m128i a_coeffs0[8];
    a_coeffs0[0] = _mm_lddqu_si128((__m128i*)&a->coeffs[0]);
    for (i=1; i<8; i++)
        a_coeffs0[i] = _mm_slli_si128(a_coeffs0[i-1], 2);

    /* add coefficients that are multiplied by 1 */
    for (i=0; i<b->num_ones; i++) {
        int16_t k = b->ones[i];
        /* process the first num_coeffs0 coefficients, 1<=num_coeffs0<=8 */
        uint8_t num_bytes0 = 16 - (((size_t)&c_coeffs[k])%16);
        uint8_t num_coeffs0 = num_bytes0 / 2;   // c_coeffs[k+num_coeffs0] is 16-byte aligned
        k -= 8 - num_coeffs0;
        __m128i *ck = (__m128i*)&c_coeffs[k];
        __m128i aj = a_coeffs0[8-num_coeffs0];
        __m128i ca = _mm_add_epi16(*ck, aj);
        _mm_storeu_si128(ck, ca);
        k += 8;
        /* process the remaining coefficients in blocks of 8. */
        /* it is safe not to truncate the last block of 8 coefficients */
        /* because there is extra room at the end of the coeffs array  */
        ck = (__m128i*)&c_coeffs[k];
        int16_t j;
        for (j=num_coeffs0; j<N; j+=8,k+=8) {
            __m128i aj = _mm_lddqu_si128((__m128i*)&a->coeffs[j]);
            __m128i ca = _mm_add_epi16(*ck, aj);
            _mm_storeu_si128(ck, ca);
            ck++;
        }
    }

    /* subtract coefficients that are multiplied by -1 */
    for (i=0; i<b->num_neg_ones; i++) {
        int16_t k = b->neg_ones[i];
        /* process the first num_coeffs0 coefficients, 1<=num_coeffs0<=8 */
        uint8_t num_bytes0 = 16 - (((size_t)&c_coeffs[k])%16);
        uint8_t num_coeffs0 = num_bytes0 / 2;   // c_coeffs[k+num_coeffs0] is 16-byte aligned
        k -= 8 - num_coeffs0;
        __m128i *ck = (__m128i*)&c_coeffs[k];
        __m128i aj = a_coeffs0[8-num_coeffs0];
        __m128i ca = _mm_sub_epi16(*ck, aj);
        _mm_storeu_si128(ck, ca);
        k += 8;
        /* process the remaining coefficients in blocks of 8. */
        /* it is safe not to truncate the last block of 8 coefficients */
        /* because there is extra room at the end of the coeffs array  */
        ck = (__m128i*)&c_coeffs[k];
        int16_t j;
        for (j=num_coeffs0; j<N; j+=8,k+=8) {
            __m128i aj = _mm_lddqu_si128((__m128i*)&a->coeffs[j]);
            __m128i ca = _mm_sub_epi16(*ck, aj);
            _mm_storeu_si128(ck, ca);
            ck++;
        }
    }
    for (i=0; i<N; i++)
        c_coeffs[i] = c_coeffs[i] + c_coeffs[N+i];
    memcpy(&c->coeffs, c_coeffs, N*2);

    c->N = N;
    ntru_mod(c, modulus);
    return 1;
}

uint8_t ntru_mult_tern_sse(NtruIntPoly *a, NtruTernPoly *b, NtruIntPoly *c, uint16_t modulus) {
    if (b->num_ones<NTRU_SPARSE_THRESH && b->num_neg_ones<NTRU_SPARSE_THRESH)
        return ntru_mult_tern_sse_sparse(a, b, c, modulus);
    else
        return ntru_mult_tern_sse_dense(a, b, c, modulus);
}
#endif   /* __SSSE3__ */

#ifndef NTRU_AVOID_HAMMING_WT_PATENT
uint8_t ntru_mult_prod(NtruIntPoly *a, NtruProdPoly *b, NtruIntPoly *c, uint16_t modulus) {
    uint16_t N = a->N;
    if (N != b->N)
        return 0;
    c->N = N;
    memset(&c->coeffs, 0, N * sizeof c->coeffs[0]);

    NtruIntPoly temp;
    ntru_mult_tern(a, &b->f1, &temp, modulus);
    ntru_mult_tern(&temp, &b->f2, c, modulus);
    NtruIntPoly f3a;
    ntru_mult_tern(a, &b->f3, &f3a, modulus);
    ntru_add_int(c, &f3a);

    ntru_mod(c, modulus);
    return 1;
}
#endif   /* NTRU_AVOID_HAMMING_WT_PATENT */

uint8_t ntru_mult_priv(NtruPrivPoly *a, NtruIntPoly *b, NtruIntPoly *c, uint16_t modulus) {
#ifndef NTRU_AVOID_HAMMING_WT_PATENT
    if (a->prod_flag)
        return ntru_mult_prod(b, &a->poly.prod, c, modulus);
    else
#endif   /* NTRU_AVOID_HAMMING_WT_PATENT */
        return ntru_mult_tern(b, &a->poly.tern, c, modulus);
}

void ntru_tern_to_int(NtruTernPoly *a, NtruIntPoly *b) {
    memset(&b->coeffs, 0, a->N * sizeof b->coeffs[0]);
    uint16_t i;
    for (i=0; i<a->num_ones; i++)
        b->coeffs[a->ones[i]] = 1;
    for (i=0; i<a->num_neg_ones; i++)
        b->coeffs[a->neg_ones[i]] = -1;

    b->N = a->N;
}

#ifndef NTRU_AVOID_HAMMING_WT_PATENT
void ntru_prod_to_int(NtruProdPoly *a, NtruIntPoly *b, uint16_t modulus) {
    memset(&b->coeffs, 0, a->N * sizeof b->coeffs[0]);
    b->N = a->N;
    NtruIntPoly c;
    ntru_tern_to_int(&a->f1, &c);
    ntru_mult_tern(&c, &a->f2, b, modulus);
    ntru_add_tern(b, &a->f3);
}
#endif   /* NTRU_AVOID_HAMMING_WT_PATENT */

void ntru_priv_to_int(NtruPrivPoly *a, NtruIntPoly *b, uint16_t modulus) {
#ifndef NTRU_AVOID_HAMMING_WT_PATENT
    if (a->prod_flag)
        ntru_prod_to_int(&a->poly.prod, b, modulus);
    else
#endif   /* NTRU_AVOID_HAMMING_WT_PATENT */
        ntru_tern_to_int(&a->poly.tern, b);
}

/** NtruPrivPoly to binary (coefficients reduced mod 2) */
void ntru_priv_to_mod2(NtruPrivPoly *a, uint64_t *b_coeffs64) {
#ifndef NTRU_AVOID_HAMMING_WT_PATENT
    if (a->prod_flag) {
        NtruProdPoly *prod = &a->poly.prod;
        uint16_t N = prod->N;
        uint16_t N64 = (prod->N+63) / 64;
        memset(b_coeffs64, 0, N64*8);
        uint16_t i, j, bidx;
        for (i=0; i<prod->f1.num_ones; i++) {
            for (j=0; j<prod->f2.num_ones; j++) {
                bidx = prod->f1.ones[i] + prod->f2.ones[j];
                if (bidx >= N)
                    bidx -= N;
                b_coeffs64[bidx/64] ^= ((uint64_t)1) << (bidx%64);
            }
            for (j=0; j<prod->f2.num_neg_ones; j++) {
                bidx = prod->f1.ones[i] + prod->f2.neg_ones[j];
                if (bidx >= N)
                    bidx -= N;
                b_coeffs64[bidx/64] ^= ((uint64_t)1) << (bidx%64);
            }
        }
        for (i=0; i<prod->f1.num_neg_ones; i++) {
            for (j=0; j<prod->f2.num_ones; j++) {
                bidx = prod->f1.neg_ones[i] + prod->f2.ones[j];
                if (bidx >= N)
                    bidx -= N;
                b_coeffs64[bidx/64] ^= ((uint64_t)1) << (bidx%64);
            }
            for (j=0; j<prod->f2.num_neg_ones; j++) {
                bidx = prod->f1.neg_ones[i] + prod->f2.neg_ones[j];
                if (bidx >= N)
                    bidx -= N;
                b_coeffs64[bidx/64] ^= ((uint64_t)1) << (bidx%64);
            }
        }
        for (i=0; i<prod->f3.num_ones; i++) {
            uint16_t ai = prod->f3.ones[i];
            b_coeffs64[ai/64] ^= ((uint64_t)1) << (ai%64);
        }
        for (i=0; i<prod->f3.num_neg_ones; i++) {
            uint16_t ai = prod->f3.neg_ones[i];
            b_coeffs64[ai/64] ^= ((uint64_t)1) << (ai%64);
        }
    }
    else
#endif   /* NTRU_AVOID_HAMMING_WT_PATENT */
    {
        NtruTernPoly *tern = &a->poly.tern;
        uint16_t N64 = (tern->N+63) / 64;
        memset(b_coeffs64, 0, N64*8);
        uint16_t i;
        for (i=0; i<tern->num_ones; i++) {
            uint16_t ai = tern->ones[i];
            b_coeffs64[ai/64] ^= ((uint64_t)1) << (ai%64);
        }
        for (i=0; i<tern->num_neg_ones; i++) {
            uint16_t ai = tern->neg_ones[i];
            b_coeffs64[ai/64] ^= ((uint64_t)1) << (ai%64);
        }
    }
}

void ntru_to_arr_64(NtruIntPoly *p, uint16_t q, uint8_t *a) {
    uint16_t N = p->N;
    uint8_t log_q = ntru_log2(q);
    typedef uint64_t __attribute__((__may_alias__)) *uint64_t_alias;
    uint64_t *a64 = (uint64_t_alias)a;
    uint16_t a_idx = 0;   /* index into a64 */
    uint8_t bit_idx = 0;   /* next unused bit of a64[a_idx] */
    a64[0] = 0;
    uint16_t p_idx;
    uint64_t mod_mask = q - 1;
    for (p_idx=0; p_idx<N; p_idx++) {
        uint64_t coeff = p->coeffs[p_idx] & mod_mask;
        if (bit_idx < 64-log_q) {
            a64[a_idx] |= coeff << bit_idx;
            bit_idx += log_q;
        }
        else {
            a64[a_idx] |= coeff << bit_idx;
            a_idx++;
            bit_idx += log_q - 64;
            a64[a_idx] = coeff >> (log_q-bit_idx);
        }
    }

    /* reverse byte order on big-endian machines */
    uint16_t i;
    for (i=0; i<=a_idx; i++)
        a64[i] = htole64(a64[i]);
}

void ntru_to_arr_16(NtruIntPoly *p, uint16_t q, uint8_t *a) {
    uint8_t bits_coeff = 0;
    while (q > 1) {
        q /= 2;
        bits_coeff++;
    }

    uint8_t bit_idx = 0;
    uint16_t byte_idx = 0;
    uint16_t i, j;
    a[0] = 0;
    for (i=0; i<p->N; i++)
        for (j=0; j<bits_coeff; j++) {
            uint8_t curr_bit = (p->coeffs[i] >> j) & 1;
            a[byte_idx] |= curr_bit << bit_idx;
            if (bit_idx == 7) {
                bit_idx = 0;
                byte_idx++;
                a[byte_idx] = 0;
            }
            else
                bit_idx++;
        }
}

#ifdef __SSSE3__
void ntru_to_arr_sse_2048(NtruIntPoly *p, uint8_t *a) {
    /* mask{n} masks bits n..n+10 except for mask64 which masks bits 64..66 */
    __m128i mask0 = {(1<<11)-1, 0};
    __m128i mask11 = _mm_slli_epi64(mask0, 11);
    __m128i mask22 = _mm_slli_epi64(mask11, 11);
    __m128i mask33 = _mm_slli_epi64(mask22, 11);
    __m128i mask44 = _mm_slli_epi64(mask33, 11);
    __m128i mask55 = {(uint64_t)((1<<9)-1) << 55, 3};
    __m128i mask64 = {0, 3};
    __m128i mask66 = {0, ((1<<11)-1) << 2};
    __m128i mask77 = _mm_slli_epi64(mask66, 11);
    __m128i mask88 = _mm_slli_epi64(mask77, 11);
    __m128i mask99 = _mm_slli_epi64(mask88, 11);

    uint16_t a_idx = 0;
    uint16_t p_idx;
    uint16_t N = p->N;
    for (p_idx=0; p_idx<N-10; p_idx+=8) {
        __m128i p128 = _mm_lddqu_si128((__m128i*)&p->coeffs[p_idx]);   /* 8 coeffs of p starting at p_idx */
        __m128i a128 = _mm_and_si128(p128, mask0);                                  /* bits [0..10]    -> [0..10]  */
        a128 = _mm_or_si128(a128, _mm_and_si128(_mm_srli_epi64(p128, 5), mask11));       /* [16..26]   -> [11..21] */
        a128 = _mm_or_si128(a128, _mm_and_si128(_mm_srli_epi64(p128, 10), mask22));      /* [32..42]   -> [22..32] */
        a128 = _mm_or_si128(a128, _mm_and_si128(_mm_srli_epi64(p128, 15), mask33));      /* [48..58]   -> [33..43] */
        __m128i p128_64 = _mm_srli_si128(p128, 8);
        a128 = _mm_or_si128(a128, _mm_and_si128(_mm_slli_epi64(p128_64, 44), mask44));   /* [64..74]   -> [44..54] */
        a128 = _mm_or_si128(a128, _mm_and_si128(_mm_slli_epi64(p128_64, 39), mask55));   /* [80..88]   -> [55..63] */
        a128 = _mm_or_si128(a128, _mm_and_si128(_mm_srli_epi64(p128, 25), mask64));      /* [89..90]   -> [64..65] */
        a128 = _mm_or_si128(a128, _mm_and_si128(_mm_srli_epi64(p128, 30), mask66));      /* [96..111]  -> [66..76] */
        a128 = _mm_or_si128(a128, _mm_and_si128(_mm_srli_epi64(p128, 35), mask77));      /* [112..127] -> [77..87] */
        _mm_storeu_si128((__m128i*)&a[a_idx], a128);
        a_idx += 11;
    }

    /* remaining coeffs (up to 10) */
    __m128i p128 = _mm_lddqu_si128((__m128i*)&p->coeffs[p_idx]);   /* 8 coeffs of p starting at p_idx */
    __m128i a128 = _mm_setzero_si128();
    if (N-p_idx > 0)
        a128 = _mm_and_si128(p128, mask0);                                          /* bits [0..10]    -> [0..10]  */
    if (N-p_idx > 1)
        a128 = _mm_or_si128(a128, _mm_and_si128(_mm_srli_epi64(p128, 5), mask11));       /* [16..26]   -> [11..21] */
    if (N-p_idx > 2)
        a128 = _mm_or_si128(a128, _mm_and_si128(_mm_srli_epi64(p128, 10), mask22));      /* [32..42]   -> [22..32] */
    if (N-p_idx > 3)
        a128 = _mm_or_si128(a128, _mm_and_si128(_mm_srli_epi64(p128, 15), mask33));      /* [48..58]   -> [33..43] */
    __m128i p128_64 = _mm_srli_si128(p128, 8);
    if (N-p_idx > 4)
        a128 = _mm_or_si128(a128, _mm_and_si128(_mm_slli_epi64(p128_64, 44), mask44));   /* [64..74]   -> [44..54] */
    if (N-p_idx > 5) {
        a128 = _mm_or_si128(a128, _mm_and_si128(_mm_slli_epi64(p128_64, 39), mask55));   /* [80..88]   -> [55..63] */
        a128 = _mm_or_si128(a128, _mm_and_si128(_mm_srli_epi64(p128, 25), mask64));      /* [89..90]   -> [64..65] */
    }
    if (N-p_idx > 6)
        a128 = _mm_or_si128(a128, _mm_and_si128(_mm_srli_epi64(p128, 30), mask66));      /* [96..111]  -> [66..76] */
    if (N-p_idx > 7)
        a128 = _mm_or_si128(a128, _mm_and_si128(_mm_srli_epi64(p128, 35), mask77));      /* [112..127] -> [77..87] */
    if (N-p_idx > 8) {
        p128 = _mm_lddqu_si128((__m128i*)&p->coeffs[p_idx+8]);           /* coeffs p_idx+8 through p_idx+15 */
        p128_64 = _mm_slli_si128(p128, 8);
        a128 = _mm_or_si128(a128, _mm_and_si128(_mm_slli_epi64(p128_64, 24), mask88));  /* [0..15]    -> [88..98]  */
    }
    if (N-p_idx > 9)
        a128 = _mm_or_si128(a128, _mm_and_si128(_mm_slli_epi64(p128_64, 19), mask99));  /* [16..31]   -> [99..109] */
    uint8_t a_last[16];
    _mm_storeu_si128((__m128i*)a_last, a128);
    memcpy(&a[a_idx], a_last, ((N-p_idx)*11+7)/8);
}
#endif   /* __SSSE3__ */

void ntru_to_arr(NtruIntPoly *p, uint16_t q, uint8_t *a) {
#ifdef __SSSE3__
    if (q == 2048)
        ntru_to_arr_sse_2048(p, a);
    else
        ntru_to_arr_16(p, q, a);
#elif _LP64
    ntru_to_arr_64(p, q, a);
#else
    ntru_to_arr_16(p, q, a);
#endif
}

void ntru_to_arr4(NtruIntPoly *p, uint8_t *arr) {
    uint16_t i = 0;
    while (i < p->N-3) {
        int8_t c0 = p->coeffs[i] & 3;
        int8_t c1 = p->coeffs[i+1] & 3;
        int8_t c2 = p->coeffs[i+2] & 3;
        int8_t c3 = p->coeffs[i+3] & 3;
        int16_t d = c0 + (c1<<2) + (c2<<4) + (c3<<6);
        arr[i/4] = d;
        i += 4;
    }

    /* handle the last 0 to 3 coefficients */
    if (i >= p->N)
        return;
    uint16_t last = i / 4;
    arr[last] = p->coeffs[i] & 3;
    i++;

    if (i >= p->N)
        return;
    arr[last] |= (p->coeffs[i]&3) << 2;
    i++;

    if (i >= p->N)
        return;
    arr[last] |= (p->coeffs[i]&3) << 4;
    i++;

    if (i >= p->N)
        return;
    arr[last] |= (p->coeffs[i]&3) << 6;
}

void ntru_from_arr(uint8_t *arr, uint16_t N, uint16_t q, NtruIntPoly *p) {
    p->N = N;
    memset(&p->coeffs, 0, N * sizeof p->coeffs[0]);

    uint8_t bits_per_coeff = 0;
    while (q > 1) {
        q /= 2;
        bits_per_coeff++;
    }

    uint32_t mask = 0xFFFFFFFF >> (32-bits_per_coeff);   /* for truncating values to bitsPerCoeff bits */
    uint16_t byte_idx = 0;
    uint8_t bit_idx = 0;   /* next bit in arr[byte_idx] */
    uint32_t coeff_buf = 0;   /* contains (bit_idx) bits */
    uint8_t coeff_bits = 0;   /* length of coeffBuf */
    uint16_t coeff_idx = 0;   /* index into coeffs */
    while (coeff_idx < N) {
        /* copy bits_per_coeff or more into coeff_buf */
        while (coeff_bits < bits_per_coeff) {
            coeff_buf += (arr[byte_idx]&0xFF) << coeff_bits;
            coeff_bits += 8 - bit_idx;
            byte_idx++;
            bit_idx = 0;
        }

        /* low bits_per_coeff bits = next coefficient */
        p->coeffs[coeff_idx] = coeff_buf & mask;
        coeff_idx++;

        coeff_buf >>= bits_per_coeff;
        coeff_bits -= bits_per_coeff;
    }
}

void ntru_mult_fac(NtruIntPoly *a, int16_t factor) {
    uint16_t i;
    for (i=0; i<a->N; i++)
        a->coeffs[i] *= factor;
}

void ntru_mult_2(NtruIntPoly *a, uint16_t modulus) {
    uint16_t i;
    for (i=0; i<a->N; i++)
        a->coeffs[i] = (a->coeffs[i]*2) % modulus;
}

NtruIntPoly *ntru_zero_poly(uint16_t n) {
    NtruIntPoly *poly = calloc(1, sizeof *poly);
    if (poly) {
        poly->N = n;
        memset(&poly->coeffs, 0, n * sizeof poly->coeffs[0]);
    }
    return poly;
}

NtruIntPoly *ntru_clone(NtruIntPoly *a) {
    NtruIntPoly *b = malloc(sizeof *a);
    memcpy(b, a, sizeof *a);
    return b;
}

#ifdef __SSSE3__
void ntru_mod_sse(NtruIntPoly *p, uint16_t modulus) {
    uint16_t i;
    __m128i mod_mask = _mm_set1_epi16(modulus - 1);

    for (i=0; i<p->N; i+=8) {
        __m128i a = _mm_lddqu_si128((__m128i*)&p->coeffs[i]);
        a = _mm_and_si128(a, mod_mask);
        _mm_storeu_si128((__m128i*)&p->coeffs[i], a);
    }
}
#endif

void ntru_mod_64(NtruIntPoly *p, uint16_t modulus) {
    typedef uint64_t __attribute__((__may_alias__)) uint64_t_alias;
    uint16_t i;
    if (modulus == 20480)
        for (i=0; i<p->N; i+=4)
            *((uint64_t_alias*)&p->coeffs[i]) &= 0x07FF07FF07FF07FF;
    else {
        uint64_t mod_mask = modulus - 1;
        mod_mask += mod_mask << 16;
        mod_mask += mod_mask << 32;
        for (i=0; i<p->N; i+=4)
            *((uint64_t_alias*)&p->coeffs[i]) &= mod_mask;
    }
}

void ntru_mod_16(NtruIntPoly *p, uint16_t modulus) {
    uint16_t i;
    if (modulus == 2048)
        for (i=0; i<p->N; i++)
            p->coeffs[i] &= 2047;
    else {
        uint16_t mod_mask = modulus - 1;
        for (i=0; i<p->N; i++)
            p->coeffs[i] &= mod_mask;
    }
}

void ntru_mod(NtruIntPoly *p, uint16_t modulus) {
#ifdef __SSSE3__
    ntru_mod_sse(p, modulus);
#elif _LP64
    ntru_mod_64(p, modulus);
#else
    ntru_mod_16(p, modulus);
#endif
}

void ntru_mod3_standard(NtruIntPoly *p) {
    uint16_t i;
    for (i=0; i<p->N; i++) {
        int8_t c = p->coeffs[i] % 3;
        if (c > 1)
            c = -1;
        if (c < -1)
            c = 1;
        p->coeffs[i] = c;
    }
}

#ifdef __SSSE3__
/* (i%3)+3 for i=0..7 */
__m128i NTRU_MOD3_LUT = {0x0403020403020403, 0};

/**
 * SSE version of ntru_mod3.
 * Based on Douglas W Jones' mod3 function at
 * http://homepage.cs.uiowa.edu/~jones/bcd/mod.shtml.
 */
void ntru_mod3_sse(NtruIntPoly *p) {
    uint16_t i;
    for (i=0; i<(p->N+7)/8*8; i+=8) {
        __m128i a = _mm_lddqu_si128((__m128i*)&p->coeffs[i]);

        /* make positive */
        __m128i _3000 = _mm_set1_epi16(3000);
        a = _mm_add_epi16(a, _3000);

        /* a = (a>>8) + (a&0xFF);  (sum base 2**8 digits) */
        __m128i a1 = _mm_srli_epi16(a, 8);
        __m128i mask = _mm_set1_epi16(0x00FF);
        __m128i a2 = _mm_and_si128(a, mask);
        a = _mm_add_epi16(a1, a2);

        /* a = (a>>4) + (a&0xF);  (sum base 2**4 digits; worst case 0x3B) */
        a1 = _mm_srli_epi16(a, 4);
        mask = _mm_set1_epi16(0x000F);
        a2 = _mm_and_si128(a, mask);
        a = _mm_add_epi16(a1, a2);
        /* a = (a>>2) + (a&0x3);  (sum base 2**2 digits; worst case 0x1B) */
        a1 = _mm_srli_epi16(a, 2);
        mask = _mm_set1_epi16(0x0003);
        a2 = _mm_and_si128(a, mask);
        a = _mm_add_epi16(a1, a2);

        /* a = (a>>2) + (a&0x3);  (sum base 2**2 digits; worst case 0x7) */
        a1 = _mm_srli_epi16(a, 2);
        mask = _mm_set1_epi16(0x0003);
        a2 = _mm_and_si128(a, mask);
        a = _mm_add_epi16(a1, a2);

        __m128i a_mod3 = _mm_shuffle_epi8(NTRU_MOD3_LUT, a);
        /* _mm_shuffle_epi8 changed bytes 1, 3, 5, ... to non-zero; change them back to zero */
        mask = _mm_set1_epi16(0x00FF);
        a_mod3 = _mm_and_si128(a_mod3, mask);
        /* subtract 3 so coefficients are in the -1..1 range */
        __m128i three = _mm_set1_epi16(0x0003);
        a_mod3 = _mm_sub_epi16(a_mod3, three);

        _mm_storeu_si128((__m128i*)&p->coeffs[i], a_mod3);
    }
}
#endif   /* __SSSE3__ */

void ntru_mod3(NtruIntPoly *p) {
#ifdef __SSSE3__
    ntru_mod3_sse(p);
#else
    ntru_mod3_standard(p);
#endif   /* __SSSE3__ */
}

void ntru_mod_center(NtruIntPoly *p, uint16_t modulus) {
    uint16_t i;
    if (modulus == 2048)
        for (i=0; i<p->N; i++) {
            int16_t c = p->coeffs[i] & 2047;
            if (c & 1024)
                c -= 2048;
            p->coeffs[i] = c;
        }
    else {
        uint16_t m2 = modulus / 2;
        for (i=0; i<p->N; i++) {
            int16_t c = p->coeffs[i] % modulus;
            if (c < -m2)
                c += modulus;
            if (c > m2)
                c -= modulus;
            p->coeffs[i] = c;
        }
    }
}

void ntru_mod2(NtruIntPoly *p) {
    uint16_t i;
    for (i=0; i<p->N; i++)
        p->coeffs[i] &= 1;
}

uint8_t ntru_equals0(NtruIntPoly *p) {
    uint16_t i;
    for (i=0; i<p->N; i++)
        if (p->coeffs[i] != 0)
            return 0;
    return 1;
}

uint8_t ntru_equals0_64(uint64_t *p, uint16_t len) {
    uint16_t i;
    for (i=0; i<len; i++)
        if (p[i] != 0)
            return 0;
    return 1;
}

uint8_t ntru_equals1(NtruIntPoly *p) {
    uint16_t i;
    for (i=1; i<p->N; i++)
        if (p->coeffs[i] != 0)
            return 0;
    return p->coeffs[0] == 1;
}

uint8_t ntru_equals_int(NtruIntPoly *a, NtruIntPoly *b) {
    if (a->N != b->N)
        return 0;

    uint16_t i;
    for (i=0; i<a->N; i++)
        if (a->coeffs[i] != b->coeffs[i])
            return 0;

    return 1;
}

uint16_t ntru_deg(NtruIntPoly *p) {
    uint16_t deg = p->N - 1;
    while (deg>0 && p->coeffs[deg]==0)
        deg--;
    return deg;
}

uint16_t ntru_deg_64(uint64_t *coeffs, uint16_t len) {
    uint16_t deg = 64*len - 1;
    len--;
    while (len>0 && coeffs[len]==0) {
        len--;
        deg -= 64;
    }
    while (coeffs[len]>>(deg%64)==0 && deg>0)
        deg--;
    return deg;
}

void ntru_clear_tern(NtruTernPoly *p) {
    memset(&p->ones, 0, p->num_ones * sizeof p->ones[0]);
    memset(&p->neg_ones, 0, p->num_neg_ones * sizeof p->neg_ones[0]);
}

void ntru_clear_priv(NtruPrivPoly *p) {
#ifndef NTRU_AVOID_HAMMING_WT_PATENT
    if (p->prod_flag) {
        ntru_clear_tern(&p->poly.prod.f1);
        ntru_clear_tern(&p->poly.prod.f2);
        ntru_clear_tern(&p->poly.prod.f3);
    }
    else
#endif   /* NTRU_AVOID_HAMMING_WT_PATENT */
        ntru_clear_tern(&p->poly.tern);
}

void ntru_clear_int(NtruIntPoly *p) {
    uint16_t i;
    for (i=0; i<p->N; i++)
        p->coeffs[i] = 0;
}

/**
 * @brief Lift inverse
 *
 * Given a polynomial a and the inverse of (1+3a) mod 2, this function
 * calculates the inverse of (1+3a) mod q.
 *
 * @param a a polynomial such that Fq = (1+3a)^(-1) (mod 2)
 * @param Fq the inverse of 1+3a modulo 2
 * @param q the modulus
 */
void ntru_mod2_to_modq(NtruPrivPoly *a, NtruIntPoly *Fq, uint16_t q) {
    NtruIntPoly temp1, temp2;
    uint32_t v = 2;
    while (v < q) {
        v *= v;

        /* temp1 = (1+3a)*Fq */
        ntru_mult_priv(a, Fq, &temp1, q);
        ntru_mult_fac(&temp1, 3);
        ntru_add_int(&temp1, Fq);

        ntru_neg_mod(&temp1, q);
        temp1.coeffs[0] += 2;
        memcpy(&temp2, Fq, sizeof *Fq);
        ntru_mult_int(&temp1, &temp2, Fq, q);
    }
}

uint8_t ntru_invert(NtruPrivPoly *a, uint16_t q, NtruIntPoly *Fq) {
#ifdef _LP64
    return ntru_invert_64(a, q, Fq);
#else
    return ntru_invert_16(a, q, Fq);
#endif
}

uint8_t ntru_invert_16(NtruPrivPoly *a, uint16_t q, NtruIntPoly *Fq) {
    uint8_t invertible;
    int16_t i;
#ifndef NTRU_AVOID_HAMMING_WT_PATENT
    uint16_t N = a->prod_flag ? a->poly.prod.N : a->poly.tern.N;
#else
    uint16_t N = a->poly.tern.N;
#endif   /* NTRU_AVOID_HAMMING_WT_PATENT */
    uint16_t k = 0;
    NtruIntPoly *b = ntru_zero_poly(N+1);
    if (!b)
        return NTRU_ERR_OUT_OF_MEMORY;
    b->coeffs[0] = 1;
    NtruIntPoly *c = ntru_zero_poly(N+1);
    if (!c) {
        free(b);
        return NTRU_ERR_OUT_OF_MEMORY;
    }
    NtruIntPoly *f = malloc(sizeof(NtruIntPoly));
    if (!f) {
        free(b);
        free(c);
        return NTRU_ERR_OUT_OF_MEMORY;
    }
    /* f=3a+1; skip multiplication by 3 because f is taken mod 2 later */
    ntru_priv_to_int(a, f, q);
    f->coeffs[0] += 1;
    /* add one coefficient for a total of N+1 */
    f->coeffs[f->N] = 0;
    f->N++;
    ntru_mod2(f);
    /* set g(x) = x^N − 1 */
    NtruIntPoly *g = ntru_zero_poly(N+1);
    if (!g) {
        free(b);
        free(c);
        free(f);
        return NTRU_ERR_OUT_OF_MEMORY;
    }
    g->coeffs[0] = 1;
    g->coeffs[N] = 1;
    for (;;) {
        while (f->coeffs[0] == 0) {
            for (i=1; i<=N; i++) {
                f->coeffs[i-1] = f->coeffs[i];   /* f(x) = f(x) / x */
                c->coeffs[N+1-i] = c->coeffs[N-i];   /* c(x) = c(x) * x */
            }
            f->coeffs[N] = 0;
            c->coeffs[0] = 0;
            k++;
            if (ntru_equals0(f)) {
                invertible = 0;
                goto done;
            }
        }
        if (ntru_equals1(f))
            break;
        if (ntru_deg(f) < ntru_deg(g)) {
            /* exchange f and g */
            NtruIntPoly *temp = f;
            f = g;
            g = temp;
            /* exchange b and c */
            temp = b;
            b = c;
            c = temp;
        }
        ntru_add_int_mod2(f, g);
        ntru_add_int_mod2(b, c);
    }

    if (b->coeffs[N] != 0) {
        invertible = 0;
        goto done;
    }
    invertible = 1;

    /* Fq(x) = x^(N-k) * b(x) */
    memset(&Fq->coeffs, 0, N * sizeof Fq->coeffs[0]);
    Fq->N = N;
    int16_t j = 0;
    k %= N;
    for (i=N-1; i>=0; i--) {
        j = i - k;
        if (j < 0)
            j += N;
        Fq->coeffs[j] = b->coeffs[i];
    }

    ntru_mod2_to_modq(a, Fq, q);

done:
    free(b);
    free(c);
    free(f);
    free(g);

    return invertible;
}

uint8_t ntru_invert_64(NtruPrivPoly *a, uint16_t q, NtruIntPoly *Fq) {
    int16_t i;
#ifndef NTRU_AVOID_HAMMING_WT_PATENT
    uint16_t N = a->prod_flag ? a->poly.prod.N : a->poly.tern.N;
#else
    uint16_t N = a->poly.tern.N;
#endif   /* NTRU_AVOID_HAMMING_WT_PATENT */
    uint16_t k = 0;
    uint16_t N64 = (N+1+63) / 64;   /* #uint64_t's needed for N+1 coeffs */

    /* b = 1 */
    uint64_t b_coeffs64_arr[N64];
    uint64_t *b_coeffs64 = b_coeffs64_arr;
    memset(b_coeffs64+1, 0, (N64-1)*8);
    b_coeffs64[0] = 1;

    /* c = 0 */
    uint64_t c_coeffs64_arr[N64];
    uint64_t *c_coeffs64 = c_coeffs64_arr;
    memset(c_coeffs64, 0, N64*8);

    /* f=3a+1; skip multiplication by 3 because f=3f (mod 2) */
    uint64_t f_coeffs64_arr[N64];
    uint64_t *f_coeffs64 = f_coeffs64_arr;
    ntru_priv_to_mod2(a, f_coeffs64);
    f_coeffs64[0] ^= 1;

    /* g(x) = x^N − 1 */
    uint64_t g_coeffs64_arr[N64];
    uint64_t *g_coeffs64 = g_coeffs64_arr;
    memset(g_coeffs64, 0, N64*8);
    g_coeffs64[0] = 1;
    g_coeffs64[N/64] |= ((uint64_t)1) << (N%64);

    uint16_t deg_f = ntru_deg_64(f_coeffs64, N64);
    uint16_t deg_g = N;
    for (;;) {
        uint16_t num_zeros = 0;
        /* while f[0]==0 */
        while ((f_coeffs64[num_zeros/64]&(((uint64_t)1)<<(num_zeros%64)))==0 && num_zeros<=N)
            num_zeros++;
        if (num_zeros >= N)   /* not invertible */
            return 0;
        k += num_zeros;

        /* right-shift f, left-shift c num_zeros coefficients each */
        if (num_zeros >= 64) {
            memmove(c_coeffs64+num_zeros/64, c_coeffs64, N64*8-num_zeros/64*8);
            memset(c_coeffs64, 0, num_zeros/64*8);
            memmove(f_coeffs64, f_coeffs64+num_zeros/64, N64*8-num_zeros/64*8);
            memset(f_coeffs64+N64-num_zeros/64, 0, num_zeros/64*8);
            num_zeros %= 64;
        }
        if (num_zeros > 0) {
            /* c(x) = c(x)*(x^num_zeros) */
            for (i=N64-1; i>0; i--) {
                c_coeffs64[i] <<= num_zeros;
                c_coeffs64[i] |= c_coeffs64[i-1] >> (64-num_zeros);
            }
            c_coeffs64[0] <<= num_zeros;
            /* f(x) = f(x)/(x^num_zeros) */
            for (i=1; i<N64; i++) {
                f_coeffs64[i-1] >>= num_zeros;
                f_coeffs64[i-1] |= f_coeffs64[i] << (64-num_zeros);
            }
            f_coeffs64[i-1] >>= num_zeros;
        }
        deg_f -= num_zeros;

        if (deg_f==0 && f_coeffs64[0]==1)   /* if f==1 */
            break;
        if (deg_f < deg_g) {
            /* exchange f and g */
            uint64_t *temp_coeffs = f_coeffs64;
            f_coeffs64 = g_coeffs64;
            g_coeffs64 = temp_coeffs;
            uint16_t temp = deg_f;
            deg_f = deg_g;
            deg_g = temp;
            /* exchange b and c */
            temp_coeffs = b_coeffs64;
            b_coeffs64 = c_coeffs64;
            c_coeffs64 = temp_coeffs;
        }
        ntru_add_int_mod2_64(f_coeffs64, g_coeffs64, N64);
        ntru_add_int_mod2_64(b_coeffs64, c_coeffs64, N64);
    }

    if ((b_coeffs64[(N+1-1)/64]&(((uint64_t)1)<<((N+1-1)%64))) != 0)   /* if (b[N]!=0) */
        return 0;

    /* Fq(x) = x^(N-k) * b(x) */
    memset(&Fq->coeffs, 0, N * sizeof Fq->coeffs[0]);
    Fq->N = N;
    int16_t j = 0;
    while (k >= N)
        k -= N;
    for (i=N-1; i>=0; i--) {
        j = i - k;
        if (j < 0)
            j += N;
        Fq->coeffs[j] = (b_coeffs64[i/64]>>(i%64)) & 1;   /* Fq->coeffs[j]=b[i] */
    }

    ntru_mod2_to_modq(a, Fq, q);

    return 1;
}
