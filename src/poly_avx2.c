#ifdef __AVX2__
#include <string.h>
#include <immintrin.h>
#include "poly_avx2.h"
#include "types.h"

#define NTRU_SPARSE_THRESH_AVX2 14

uint8_t ntru_mult_int_avx2(NtruIntPoly *a, NtruIntPoly *b, NtruIntPoly *c, uint16_t mod_mask) {
    uint16_t N = a->N;
    if (N != b->N)
        return 0;
    c->N = N;
    int16_t c_coeffs[2*NTRU_INT_POLY_SIZE];   /* double capacity for intermediate result */
    memset(&c_coeffs, 0, sizeof(c_coeffs));

    uint16_t k;
    for (k=N; k<NTRU_INT_POLY_SIZE; k++) {
        a->coeffs[k] = 0;
        b->coeffs[k] = 0;
    }
    for (k=0; k<N; k+=16) {
        uint8_t j;

        __m256i b256[8];
        for (j=0; j<8; j++) {

            b256[j] = _mm256_inserti128_si256(_mm256_castsi128_si256(
                    _mm_set1_epi16(b->coeffs[k+j])),
                    _mm_set1_epi16(b->coeffs[k+8+j]),1);
        }

        /* indices 0..7 */
        __m128i tmp_a = _mm_lddqu_si128((__m128i*)&a->coeffs[0]);
        __m256i a256 = _mm256_broadcastsi128_si256(tmp_a);

        __m256i c256 = _mm256_lddqu_si256((__m256i*)&c_coeffs[k]);
        for (j=0; j<8; j++) {
            __m256i product = _mm256_mullo_epi16(a256, b256[j]);
            c256 = _mm256_add_epi16(c256, product);
            a256 = _mm256_bslli_epi128(a256, 2);
        }
        _mm256_storeu_si256((__m256i*)&c_coeffs[k], c256);

        /* indices 8... */
        uint16_t i;
        for (i=8; i<N+8; i+=8) {
            __m256i c256 = _mm256_lddqu_si256((__m256i*)&c_coeffs[k+i]);

            __m128i tmp_0 = _mm_lddqu_si128((__m128i*)&a->coeffs[i-7]);
            __m256i a256_0 = _mm256_broadcastsi128_si256(tmp_0);

            __m128i tmp_1 = _mm_lddqu_si128((__m128i*)&a->coeffs[i]);
            __m256i a256_1 = _mm256_broadcastsi128_si256(tmp_1);

            for (j=0; j<8; j++) {
                __m256i product = _mm256_mullo_epi16(a256_1, b256[j]);
                c256 = _mm256_add_epi16(c256, product);

                a256_0 = _mm256_bslli_epi128(a256_0, 2);
                a256_1 = _mm256_alignr_epi8(a256_1, a256_0, 14);
            }
            _mm256_storeu_si256((__m256i*)&c_coeffs[k+i], c256);
        }
    }

    /* no need to SSE-ify the following loop b/c the compiler auto-vectorizes it */
    for (k=0; k<N; k++)
        c->coeffs[k] = c_coeffs[k] + c_coeffs[N+k];

    ntru_mod_avx2(c, mod_mask);
    return 1;
}

/* Optimized for small df */
uint8_t ntru_mult_tern_avx2_sparse(NtruIntPoly *a, NtruTernPoly *b, NtruIntPoly *c, uint16_t mod_mask) {
    uint16_t N = a->N;
    if (N != b->N)
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
        for (j=0; j<j_end; j+=16,k+=16) {
            __m256i ck = _mm256_lddqu_si256((__m256i*)&c->coeffs[k]);
            __m256i aj = _mm256_lddqu_si256((__m256i*)&a->coeffs[j]);
            __m256i ca = _mm256_add_epi16(ck, aj);
            _mm256_storeu_si256((__m256i*)&c->coeffs[k], ca);
        }
        j = j_end;
        for (k=0; j<N-15; j+=16,k+=16) {
            __m256i ck = _mm256_lddqu_si256((__m256i*)&c->coeffs[k]);
            __m256i aj = _mm256_lddqu_si256((__m256i*)&a->coeffs[j]);
            __m256i ca = _mm256_add_epi16(ck, aj);
            _mm256_storeu_si256((__m256i*)&c->coeffs[k], ca);
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
        for (j=0; j<j_end; j+=16,k+=16) {
            __m256i ck = _mm256_lddqu_si256((__m256i*)&c->coeffs[k]);
            __m256i aj = _mm256_lddqu_si256((__m256i*)&a->coeffs[j]);
            __m256i ca = _mm256_sub_epi16(ck, aj);
            _mm256_storeu_si256((__m256i*)&c->coeffs[k], ca);
        }
        j = j_end;
        for (k=0; j<N-15; j+=16,k+=16) {
            __m256i ck = _mm256_lddqu_si256((__m256i*)&c->coeffs[k]);
            __m256i aj = _mm256_lddqu_si256((__m256i*)&a->coeffs[j]);
            __m256i ca = _mm256_sub_epi16(ck, aj);
            _mm256_storeu_si256((__m256i*)&c->coeffs[k], ca);
        }
        for (; j<N; j++,k++)
            c->coeffs[k] -= a->coeffs[j];
    }

    ntru_mod_avx2(c, mod_mask);
    return 1;
}

/* Optimized for large df */
uint8_t ntru_mult_tern_avx2_dense(NtruIntPoly *a, NtruTernPoly *b, NtruIntPoly *c, uint16_t mod_mask) {
    uint16_t N = a->N;
    if (N != b->N)
        return 0;
    c->N = N;

    uint16_t i;
    for (i=N; i<NTRU_INT_POLY_SIZE; i++)
        a->coeffs[i] = 0;
    int16_t c_coeffs_arr[16+2*NTRU_INT_POLY_SIZE];   /* double capacity for intermediate result + another 8 */
    int16_t *c_coeffs = c_coeffs_arr + 16;
    memset(&c_coeffs_arr, 0, sizeof(c_coeffs_arr));

    __m256i a_coeffs0[16];
    a_coeffs0[0] = _mm256_lddqu_si256((__m256i*)&a->coeffs[0]);

    for (i=1; i<16; i++) {
        /* Emulate the SSE full-register shifting behaviour in AVX2 (the  */
        /* corresponding _mm256_slli_si256 instruction shifts the two */
        /* 128-bit lanes independently instead of the whole register). */
        /* Two AVX2 instructions are needed for this. */
        __m256i mask = _mm256_permute2x128_si256(a_coeffs0[i-1], a_coeffs0[i-1], _MM_SHUFFLE(0,0,2,0) );
        a_coeffs0[i] = _mm256_alignr_epi8(a_coeffs0[i-1],mask,14);
    }

    /* add coefficients that are multiplied by 1 */
    for (i=0; i<b->num_ones; i++) {
        int16_t k = b->ones[i];
        /* process the first num_coeffs0 coefficients, 1<=num_coeffs0<=8 */
        uint8_t num_bytes0 = 32 - (((size_t)&c_coeffs[k])%32);
        uint8_t num_coeffs0 = num_bytes0 / 2;   /* c_coeffs[k+num_coeffs0] is 32-byte aligned */
        k -= 16 - num_coeffs0;
        __m256i *ck = (__m256i*)&c_coeffs[k];
        __m256i aj = a_coeffs0[16-num_coeffs0];
        __m256i ca = _mm256_add_epi16(*ck, aj);
        _mm256_store_si256(ck, ca);
        k += 16;
        /* process the remaining coefficients in blocks of 16. */
        /* it is safe not to truncate the last block of 16 coefficients */
        /* because there is extra room at the end of the coeffs array  */
        ck = (__m256i*)&c_coeffs[k];
        int16_t j;
        for (j=num_coeffs0; j<N; j+=16,k+=16) {
            __m256i aj = _mm256_lddqu_si256((__m256i*)&a->coeffs[j]);
            __m256i ca = _mm256_add_epi16(*ck, aj);
            _mm256_store_si256(ck, ca);
            ck++;
        }
    }

    /* subtract coefficients that are multiplied by -1 */
    for (i=0; i<b->num_neg_ones; i++) {
        int16_t k = b->neg_ones[i];
        /* process the first num_coeffs0 coefficients, 1<=num_coeffs0<=8 */
        uint8_t num_bytes0 = 32 - (((size_t)&c_coeffs[k])%32);
        uint8_t num_coeffs0 = num_bytes0 / 2;   /* c_coeffs[k+num_coeffs0] is 32-byte aligned */
        k -= 16 - num_coeffs0;
        __m256i *ck = (__m256i*)&c_coeffs[k];
        __m256i aj = a_coeffs0[16-num_coeffs0];
        __m256i ca = _mm256_sub_epi16(*ck, aj);
        _mm256_store_si256(ck, ca);
        k += 16;
        /* process the remaining coefficients in blocks of 16. */
        /* it is safe not to truncate the last block of 16 coefficients */
        /* because there is extra room at the end of the coeffs array  */
        ck = (__m256i*)&c_coeffs[k];
        int16_t j;
        for (j=num_coeffs0; j<N; j+=16,k+=16) {
            __m256i aj = _mm256_lddqu_si256((__m256i*)&a->coeffs[j]);
            __m256i ca = _mm256_sub_epi16(*ck, aj);
            _mm256_store_si256(ck, ca);
            ck++;
        }
    }

    /* reduce c_coeffs[0..2N-1] to [0..N-1] and apply mod_mask to reduce values mod q */
    /* handle the first coefficients individually if c_coeffs is not 16-byte aligned */
    for (i=0; ((size_t)&c_coeffs[i])%32; i++)
        c->coeffs[i] = (c_coeffs[i] + c_coeffs[N+i]) & mod_mask;
    /* handle the remaining ones in blocks of 16 */
    __m256i mod_mask_256 = _mm256_set1_epi16(mod_mask);
    __m256i *ci = (__m256i*)(&c_coeffs[i]);
    for (; i<N; i+=16) {
        __m256i c256_1 = _mm256_lddqu_si256((__m256i*)&c_coeffs[i+N]);
        __m256i c256_0 = _mm256_add_epi16(*ci, c256_1);
        c256_0 = _mm256_and_si256(c256_0, mod_mask_256);
        _mm256_storeu_si256((__m256i*)&c->coeffs[i], c256_0);
        ci++;
    }

    return 1;
}

uint8_t ntru_mult_tern_avx2(NtruIntPoly *a, NtruTernPoly *b, NtruIntPoly *c, uint16_t mod_mask) {
    if (b->num_ones<NTRU_SPARSE_THRESH_AVX2 && b->num_neg_ones<NTRU_SPARSE_THRESH_AVX2)
        return ntru_mult_tern_avx2_sparse(a, b, c, mod_mask);
    else
        return ntru_mult_tern_avx2_dense(a, b, c, mod_mask);
}

void ntru_mod_avx2(NtruIntPoly *p, uint16_t mod_mask) {
    uint16_t i;
    __m256i mod_mask_256 = _mm256_set1_epi16(mod_mask);

    for (i=0; i<p->N; i+=16) {
        __m256i a = _mm256_lddqu_si256((__m256i*)&p->coeffs[i]);
        a = _mm256_and_si256(a, mod_mask_256);
        _mm256_storeu_si256((__m256i*)&p->coeffs[i], a);
    }
}

__m256i NTRU_MOD3_LUT_AVX = {0x0403050403050403, 0, 0x0403050403050403, 0};

void ntru_mod3_avx2(NtruIntPoly *p) {
    uint16_t i;
    for (i=0; i<(p->N+15)/16*16; i+=16) {
        __m256i a = _mm256_lddqu_si256((__m256i*)&p->coeffs[i]);

        /* make positive */
        __m256i _3000 = _mm256_set1_epi16(3000);
        a = _mm256_add_epi16(a, _3000);

        /* a = (a>>8) + (a&0xFF);  (sum base 2**8 digits) */
        __m256i a1 = _mm256_srli_epi16(a, 8);
        __m256i mask = _mm256_set1_epi16(0x00FF);
        __m256i a2 = _mm256_and_si256(a, mask);
        a = _mm256_add_epi16(a1, a2);

        /* a = (a>>4) + (a&0xF);  (sum base 2**4 digits; worst case 0x3B) */
        a1 = _mm256_srli_epi16(a, 4);
        mask = _mm256_set1_epi16(0x000F);
        a2 = _mm256_and_si256(a, mask);
        a = _mm256_add_epi16(a1, a2);
        /* a = (a>>2) + (a&0x3);  (sum base 2**2 digits; worst case 0x1B) */
        a1 = _mm256_srli_epi16(a, 2);
        mask = _mm256_set1_epi16(0x0003);
        a2 = _mm256_and_si256(a, mask);
        a = _mm256_add_epi16(a1, a2);

        /* a = (a>>2) + (a&0x3);  (sum base 2**2 digits; worst case 0x7) */
        a1 = _mm256_srli_epi16(a, 2);
        mask = _mm256_set1_epi16(0x0003);
        a2 = _mm256_and_si256(a, mask);
        a = _mm256_add_epi16(a1, a2);

        __m256i a_mod3 = _mm256_shuffle_epi8(NTRU_MOD3_LUT_AVX, a);
        /* _mm256_shuffle_epi8 changed bytes 1, 3, 5, ... to non-zero; change them back to zero */
        mask = _mm256_set1_epi16(0x00FF);
        a_mod3 = _mm256_and_si256(a_mod3, mask);
        /* subtract 3 so coefficients are in the 0..2 range */
        __m256i three = _mm256_set1_epi16(0x0003);
        a_mod3 = _mm256_sub_epi16(a_mod3, three);

        _mm256_storeu_si256((__m256i*)&p->coeffs[i], a_mod3);
    }
}

#endif   /* __AVX2__ */
