#ifdef __SSSE3__
#include <string.h>
#include <tmmintrin.h>
#include "poly.h"   /* for ntru_to_arr_32() */
#include "poly_ssse3.h"
#include "types.h"

#define NTRU_SPARSE_THRESH_SSSE3 14

uint8_t ntru_mult_int_sse(NtruIntPoly *a, NtruIntPoly *b, NtruIntPoly *c, uint16_t mod_mask) {
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

    ntru_mod_sse(c, mod_mask);
    return 1;
}

/* Optimized for small df */
uint8_t ntru_mult_tern_sse_sparse(NtruIntPoly *a, NtruTernPoly *b, NtruIntPoly *c, uint16_t mod_mask) {
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

    ntru_mod_sse(c, mod_mask);
    return 1;
}

/* Optimized for large df */
uint8_t ntru_mult_tern_sse_dense(NtruIntPoly *a, NtruTernPoly *b, NtruIntPoly *c, uint16_t mod_mask) {
    uint16_t N = a->N;
    if (N != b->N)
        return 0;
    c->N = N;

    uint16_t i;
    for (i=N; i<NTRU_INT_POLY_SIZE; i++)
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
        uint8_t num_coeffs0 = num_bytes0 / 2;   /* c_coeffs[k+num_coeffs0] is 16-byte aligned */
        k -= 8 - num_coeffs0;
        __m128i *ck = (__m128i*)&c_coeffs[k];
        __m128i aj = a_coeffs0[8-num_coeffs0];
        __m128i ca = _mm_add_epi16(*ck, aj);
        _mm_store_si128(ck, ca);
        k += 8;
        /* process the remaining coefficients in blocks of 8. */
        /* it is safe not to truncate the last block of 8 coefficients */
        /* because there is extra room at the end of the coeffs array  */
        ck = (__m128i*)&c_coeffs[k];
        int16_t j;
        for (j=num_coeffs0; j<N; j+=8,k+=8) {
            __m128i aj = _mm_lddqu_si128((__m128i*)&a->coeffs[j]);
            __m128i ca = _mm_add_epi16(*ck, aj);
            _mm_store_si128(ck, ca);
            ck++;
        }
    }

    /* subtract coefficients that are multiplied by -1 */
    for (i=0; i<b->num_neg_ones; i++) {
        int16_t k = b->neg_ones[i];
        /* process the first num_coeffs0 coefficients, 1<=num_coeffs0<=8 */
        uint8_t num_bytes0 = 16 - (((size_t)&c_coeffs[k])%16);
        uint8_t num_coeffs0 = num_bytes0 / 2;   /* c_coeffs[k+num_coeffs0] is 16-byte aligned */
        k -= 8 - num_coeffs0;
        __m128i *ck = (__m128i*)&c_coeffs[k];
        __m128i aj = a_coeffs0[8-num_coeffs0];
        __m128i ca = _mm_sub_epi16(*ck, aj);
        _mm_store_si128(ck, ca);
        k += 8;
        /* process the remaining coefficients in blocks of 8. */
        /* it is safe not to truncate the last block of 8 coefficients */
        /* because there is extra room at the end of the coeffs array  */
        ck = (__m128i*)&c_coeffs[k];
        int16_t j;
        for (j=num_coeffs0; j<N; j+=8,k+=8) {
            __m128i aj = _mm_lddqu_si128((__m128i*)&a->coeffs[j]);
            __m128i ca = _mm_sub_epi16(*ck, aj);
            _mm_store_si128(ck, ca);
            ck++;
        }
    }

    /* reduce c_coeffs[0..2N-1] to [0..N-1] and apply mod_mask to reduce values mod q */
    /* handle the first coefficients individually if c_coeffs is not 16-byte aligned */
    for (i=0; ((size_t)&c_coeffs[i])%16; i++)
        c->coeffs[i] = (c_coeffs[i] + c_coeffs[N+i]) & mod_mask;
    /* handle the remaining ones in blocks of 8 */
    __m128i mod_mask_128 = _mm_set1_epi16(mod_mask);
    __m128i *ci = (__m128i*)(&c_coeffs[i]);
    for (; i<N; i+=8) {
        __m128i c128_1 = _mm_lddqu_si128((__m128i*)&c_coeffs[i+N]);
        __m128i c128_0 = _mm_add_epi16(*ci, c128_1);
        c128_0 = _mm_and_si128(c128_0, mod_mask_128);
        _mm_storeu_si128((__m128i*)&c->coeffs[i], c128_0);
        ci++;
    }

    return 1;
}

uint8_t ntru_mult_tern_sse(NtruIntPoly *a, NtruTernPoly *b, NtruIntPoly *c, uint16_t mod_mask) {
    if (b->num_ones<NTRU_SPARSE_THRESH_SSSE3 && b->num_neg_ones<NTRU_SPARSE_THRESH_SSSE3)
        return ntru_mult_tern_sse_sparse(a, b, c, mod_mask);
    else
        return ntru_mult_tern_sse_dense(a, b, c, mod_mask);
}

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

void ntru_to_arr_sse(NtruIntPoly *p, uint16_t q, uint8_t *a) {
    if (q == 2048)
        ntru_to_arr_sse_2048(p, a);
    else
        ntru_to_arr_32(p, q, a);
}

void ntru_mod_sse(NtruIntPoly *p, uint16_t mod_mask) {
    uint16_t i;
    __m128i mod_mask_128 = _mm_set1_epi16(mod_mask);

    for (i=0; i<p->N; i+=8) {
        __m128i a = _mm_lddqu_si128((__m128i*)&p->coeffs[i]);
        a = _mm_and_si128(a, mod_mask_128);
        _mm_storeu_si128((__m128i*)&p->coeffs[i], a);
    }
}

/* (i%3)+3 for i=0..7 */
__m128i NTRU_MOD3_LUT = {0x0403050403050403, 0};

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
        /* subtract 3 so coefficients are in the 0..2 range */
        __m128i three = _mm_set1_epi16(0x0003);
        a_mod3 = _mm_sub_epi16(a_mod3, three);

        _mm_storeu_si128((__m128i*)&p->coeffs[i], a_mod3);
    }
}

#endif   /* __SSSE3__ */
