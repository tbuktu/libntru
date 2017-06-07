#include <stdlib.h>
#include <string.h>
#include <alloca.h>
#include "poly.h"
#include "poly_ssse3.h"
#include "poly_avx2.h"
#include "rand.h"
#include "err.h"
#include "arith.h"
#include "encparams.h"
#include "ntru_endian.h"

#define NTRU_KARATSUBA_THRESH_16 40
#define NTRU_KARATSUBA_THRESH_64 120

/***************************************
 *          NTRU Prime                 *
 ***************************************/

uint8_t ntruprime_mult_poly(NtruIntPoly *a, NtruIntPoly *b, NtruIntPoly *c, uint16_t modulus) {
    uint16_t N = a->N;
    if (N != b->N)
        return 0;
    c->N = N;

    memset(&c->coeffs, 0, N * sizeof c->coeffs[0]);
    uint16_t k;
    for (k=0; k<N; k++) {
        uint64_t ck1 = 0;
        uint64_t i;
        for (i=0; i<=k; i++)
            ck1 += ((uint64_t)a->coeffs[i]) * b->coeffs[k-i];
        uint64_t ck2 = 0;
        for (i=k+1; i<N; i++)
            ck2 += ((uint64_t)a->coeffs[i]) * b->coeffs[k+N-i];
        uint64_t ck = c->coeffs[k] + ck1 + ck2;
        c->coeffs[k] = ck % modulus;
        if (k < N) {
            uint64_t ck = c->coeffs[k+1] + ck2;
            c->coeffs[k+1] = ck % modulus;
        }
    }

    return 1;
}

uint8_t ntruprime_rand_tern(uint16_t N, NtruIntPoly *poly, NtruRandContext *rand_ctx) {
    poly->N = N;
    uint16_t i;
    uint32_t arr[N];
    if (ntru_rand_generate((uint8_t*)arr, N*sizeof(arr[0]), rand_ctx) != NTRU_SUCCESS)
        return 0;
    for (i=0; i<N; i++)
        /* produces almost uniform output, there is a 1 in 2^32 chance of it being biased */
        poly->coeffs[i] = arr[i] % 3;
    return 1;
}

uint8_t ntruprime_rand_tern_t(uint16_t N, uint16_t t, NtruIntPoly *poly, NtruRandContext *rand_ctx) {
    poly->N = N;

    uint8_t rand_bits[(2*t+7)/8];
    if (ntru_rand_generate((uint8_t*)rand_bits, sizeof rand_bits, rand_ctx) != NTRU_SUCCESS)
        return 0;
    uint16_t i;
    for (i=0; i<2*t; i++) {
        uint8_t r = (rand_bits[i/8] >> (i%8)) & 1;
        poly->coeffs[i] = r ? 1 : 2;
    }
    for (; i<N; i++)
        poly->coeffs[i] = 0;

    uint32_t rand_indices[N];
    if (ntru_rand_generate((uint8_t*)rand_indices, N*sizeof(rand_indices[0]), rand_ctx) != NTRU_SUCCESS)
        return 0;

    /* Fisher-Yates shuffle */
    uint32_t rand_idx = 0;
    for (i=N-1; i>0; i--) {
        /* slightly biased; for N=739, P(poly contains a biased coeff) = 1/10798 */
        uint32_t j = rand_indices[rand_idx] % (i+1);
        uint16_t temp = poly->coeffs[i];
        poly->coeffs[i] = poly->coeffs[j];
        poly->coeffs[j] = temp;
        rand_idx++;
    }
    return 1;
}

/* Zeros a polynomial and sets the number of coefficients */
void ntruprime_zero(NtruIntPoly *a, uint16_t N) {
    a->N = N;
    memset(&a->coeffs, 0, N * sizeof a->coeffs[0]);
}

/* Reduces a NtruIntPoly modulo x^N-x-1, where N = a->N. */
void ntruprime_reduce(NtruIntPoly *a, NtruIntPoly *b, uint16_t modulus) {
    uint16_t N = a->N - 1;
    memcpy(&b->coeffs, &a->coeffs, N * sizeof a->coeffs[0]);
    b->coeffs[0] = (((uint64_t)b->coeffs[0]) + a->coeffs[N]) % modulus;
    b->coeffs[1] = (((uint64_t)b->coeffs[1]) + a->coeffs[N]) % modulus;
    b->N = N;
}

/* Copies a NtruIntPoly to another NtruIntPoly */
void ntruprime_copy(NtruIntPoly *a, NtruIntPoly *b) {
    memcpy(&b->coeffs, &a->coeffs, a->N * sizeof a->coeffs[0]);
    b->N = a->N;
}

/* Tests whether a polynomial has all zero coefficients */
uint8_t ntruprime_equals0(NtruIntPoly *a) {
    uint16_t i;
    for (i=0; i<a->N; i++)
        if (a->coeffs[i] != 0)
            return 0;
    return 1;
}

/* Returns the degree of a polynomial. Returns 0 if the polynomial equals 0. */
uint16_t ntruprime_deg(NtruIntPoly *a) {
    uint16_t i;
    for (i=a->N-1; i>0; i--)
        if (a->coeffs[i] != 0)
            return i;
    return 0;
}

/* Multiplies a polynomial by an integer */
void ntruprime_mult_mod(NtruIntPoly *a, uint16_t factor, uint16_t modulus) {
    uint16_t i;
    for (i=0; i<a->N; i++)
        a->coeffs[i] = (((uint64_t)a->coeffs[i]) * factor) % modulus;
}

/** Subtracts b*u from a; a and b are assumed to be reduced mod modulus. */
void ntruprime_subtract_multiple(NtruIntPoly *a, NtruIntPoly *b, uint16_t u, uint16_t modulus) {
    uint16_t N = a->N;
    if (b->N > N)
        N = b->N;

    uint16_t i;
    for (i=0; i<N; i++) {
        uint64_t ai = a->coeffs[i];
        ai += ((uint64_t)u) * (modulus-b->coeffs[i]);
        a->coeffs[i] = ai % modulus;
    }
}

/* Multiplies a polynomial by x^(-1) in (Z/qZ)[x][x^p-x-1] where p=a->N, q=modulus */
void ntruprime_div_x(NtruIntPoly *a, uint16_t modulus) {
    uint16_t N = a->N;
    uint64_t a0 = a->coeffs[0];
    memmove(&a->coeffs[0], &a->coeffs[1], (N-1) * sizeof a->coeffs[0]);
    a->coeffs[N-1] = a0;
    a->coeffs[0] = (((uint64_t)a->coeffs[0])-a0+modulus) % modulus;
}

/* Calculates the multiplicative inverse of a mod modulus
   using the extended Euclidean algorithm. */
uint16_t ntruprime_inv_int(uint16_t a, uint16_t modulus) {
    int16_t x = 0;
    int16_t lastx = 1;
    int16_t y = 1;
    int16_t lasty = 0;
    int16_t b = modulus;
    while (b != 0) {
        int16_t quotient = a / b;

        int16_t temp = a;
        a = b;
        b = temp % b;

        temp = x;
        x = lastx - quotient*x;
        lastx = temp;

        temp = y;
        y = lasty - quotient*y;
        lasty = temp;
    }
    if (lastx < 0)
        lastx += modulus;
    return lastx;
}

/* not constant time! */
uint8_t ntruprime_inv_poly(NtruIntPoly *a, NtruIntPoly *inv, uint16_t modulus) {
    uint16_t N = a->N;
    uint16_t k = 0;
    NtruIntPoly *b = alloca(sizeof *b);
    ntruprime_zero(b, N+1);
    b->coeffs[0] = 1;
    NtruIntPoly *c = alloca(sizeof *c);
    ntruprime_zero(c, N+1);

    /* f = a */
    NtruIntPoly *f = alloca(sizeof *f);
    f->N = N + 1;
    ntruprime_copy(a, f);
    f->coeffs[N] = 0;

    /* g = x^p - x - 1 */
    NtruIntPoly *g = alloca(sizeof *g);
    ntruprime_zero(g, N+1);
    g->coeffs[0] = modulus - 1;
    g->coeffs[1] = modulus - 1;
    g->coeffs[N] = 1;

    for (;;) {
        while (f->coeffs[0] == 0) {
            uint16_t i;

            /* f(x) = f(x) / x */
            for (i=1; i<=N; i++)
                f->coeffs[i-1] = f->coeffs[i];
            f->coeffs[N] = 0;

            /* c(x) = c(x) * x */
            for (i=N-1; i>0; i--)
                c->coeffs[i] = c->coeffs[i-1];
            c->coeffs[0] = 0;

            k++;
            if (ntruprime_equals0(f))   /* not invertible */
                return 0;
        }
        if (ntruprime_deg(f) == 0) {
            uint16_t f0_inv = ntruprime_inv_int(f->coeffs[0], modulus);
            ntruprime_mult_mod(b, f0_inv, modulus);   /* b = b * f[0]^(-1) */
            ntruprime_reduce(b, inv, modulus);
            uint16_t i;

            /* b = b * x^(-k) */
            for (i=0; i<k; i++)
                ntruprime_div_x(inv, modulus);

            return 1;
        }
        if (ntruprime_deg(f) < ntruprime_deg(g)) {
            /* exchange f and g */
            NtruIntPoly *temp = f;
            f = g;
            g = temp;
            /* exchange b and c */
            temp = b;
            b = c;
            c = temp;
        }
        /* u = f[0] * g[0]^(-1) */
        uint16_t g0_inv = ntruprime_inv_int(g->coeffs[0], modulus);
        uint16_t u = (f->coeffs[0] * (uint64_t)g0_inv) % modulus;
        ntruprime_subtract_multiple(f, g, u, modulus);   /*  f = f - u * g */
        ntruprime_subtract_multiple(b, c, u, modulus);   /*  b = b - u * c */
    }
}

/***************************************
 *          NTRUEncrypt                *
 ***************************************/

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
    uint16_t rand_data[rand_len];
    if (ntru_rand_generate((uint8_t*)rand_data, rand_len*2, rand_ctx) != NTRU_SUCCESS)
        return 0;
    uint16_t r_idx = 0;   /* index into rand_data */

    uint16_t bits = ntru_num_bits(N);
    uint16_t i = 0;
    while (i < num_ones) {
        uint16_t r = htole16(rand_data[r_idx]) >> (8*sizeof r - bits);   /* 0 <= r < 2^bits */
        r_idx++;
        /* refill rand_data if we run out */
        if (r_idx >= rand_len) {
            if (ntru_rand_generate((uint8_t*)rand_data, rand_len*2, rand_ctx) != NTRU_SUCCESS)
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
        uint16_t r = htole16(rand_data[r_idx]) >> (8*sizeof r - bits);   /* 0 <= r < 2^bits */
        r_idx++;
        /* refill rand_data if we run out */
        if (r_idx >= rand_len) {
            if (ntru_rand_generate((uint8_t*)rand_data, rand_len*2, rand_ctx) != NTRU_SUCCESS)
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

void ntru_add(NtruIntPoly *a, NtruIntPoly *b) {
    uint16_t i;
    for (i=0; i<b->N; i++)
        a->coeffs[i] += b->coeffs[i];
}

void ntru_add_mod2_32(uint32_t *a, uint32_t *b, uint16_t len) {
    uint16_t i;
    for (i=0; i<len; i++)
        a[i] ^= b[i];
}

void ntru_add_mod2_64(uint64_t *a, uint64_t *b, uint16_t len) {
    uint16_t i;
    for (i=0; i<len; i++)
        a[i] ^= b[i];
}

void ntru_sub(NtruIntPoly *a, NtruIntPoly *b) {
    uint16_t i;
    for (i=0; i<b->N; i++)
        a->coeffs[i] -= b->coeffs[i];
}

void ntru_neg_mod(NtruIntPoly *a, uint16_t modulus) {
    uint16_t i;
    for (i=0; i<a->N; i++)
        a->coeffs[i] = modulus - a->coeffs[i];
}

void ntru_mult_int_16_base(int16_t *a, int16_t *b, int16_t *c, uint16_t len, uint16_t N, uint16_t mod_mask) {
    memset(c, 0, 2*(2*len-1));   /* only needed if N < NTRU_KARATSUBA_THRESH_16 */
    uint16_t c_idx = 0;
    uint16_t k;
    for (k=0; k<2*len-1; k++) {
        int16_t ck = 0;
        uint16_t i;
        int16_t istart = k - len + 1;
        if (istart < 0)
            istart = 0;
        int16_t iend = k + 1;
        if (iend > len)
            iend = len;
        int16_t a_idx = k - istart;
        for (i=istart; i<iend; i++) {
            ck += b[i] * a[a_idx];
            a_idx--;
            if (a_idx < 0)
                a_idx = len - 1;
        }
        c[c_idx] += ck;
        c_idx++;
        if (c_idx >= N)
            c_idx = 0;
    }
}

void ntru_mult_karatsuba_16(int16_t *a, int16_t *b, int16_t *c, uint16_t len, uint16_t N) {
    if (len < NTRU_KARATSUBA_THRESH_16)
        ntru_mult_int_16_base(a, b, c, len, N, -1);
    else {
        uint16_t len2 = len / 2;
        int16_t z0[NTRU_INT_POLY_SIZE];
        int16_t z1[NTRU_INT_POLY_SIZE];
        int16_t z2[NTRU_INT_POLY_SIZE];

        /* z0, z2 */
        ntru_mult_karatsuba_16(a, b, z0, len2, N);
        ntru_mult_karatsuba_16(a+len2, b+len2, z2, len-len2, N);

        /* z1 */
        int16_t lh1[NTRU_INT_POLY_SIZE];
        int16_t lh2[NTRU_INT_POLY_SIZE];
        uint16_t i;
        for (i=0; i<len2; i++) {
            lh1[i] = a[i] + a[len2+i];
            lh2[i] = b[i] + b[len2+i];
        }
        if (len%2 != 0) {
            lh1[len-len2-1] = a[len-1];
            lh2[len-len2-1] = b[len-1];
        }
        ntru_mult_karatsuba_16(lh1, lh2, z1, len-len2, N);
        for (i=0; i<2*len2-1; i++)
            z1[i] -= z0[i];
        z1[len] = 0;
        for (i=0; i<2*(len-len2)-1; i++)
            z1[i] -= z2[i];

        /* c */
        memset(c, 0, NTRU_INT_POLY_SIZE*2);
        memcpy(c, z0, 2*(2*len2-1));   /* 2*len2-1 coefficients */
        uint16_t c_idx = len2;
        for (i=0; i<2*(len-len2)-1; i++) {
            c[c_idx] += z1[i];
            c_idx++;
            if (c_idx >= N)
                c_idx = 0;
        }
        c_idx = 2 * len2;
        if (c_idx >= N)
            c_idx = 0;
        for (i=0; i<2*(len-len2)-1; i++) {
            c[c_idx] += z2[i];
            c_idx++;
            if (c_idx >= N)
                c_idx = 0;
        }
    }
}

uint8_t ntru_mult_int_16(NtruIntPoly *a, NtruIntPoly *b, NtruIntPoly *c, uint16_t mod_mask) {
    uint16_t N = a->N;
    if (N != b->N)
        return 0;
    c->N = N;

    ntru_mult_karatsuba_16((int16_t*)&a->coeffs, (int16_t*)&b->coeffs, (int16_t*)&c->coeffs, N, N);
    ntru_mod_mask(c, mod_mask);

    return 1;
}

void ntru_mult_int_64_base(int16_t *a, int16_t *b, int16_t *c, uint16_t len, uint16_t N, uint16_t mod_mask) {
    uint16_t N2 = (len+1) / 2;
    uint64_t mod_mask_64 = mod_mask + (mod_mask<<25);

    /* make 64-bit versions of a and b */
    uint64_t a64[N2];
    uint64_t b64[N2];
    uint16_t i;
    for (i=0; i<len/2; i++) {
        a64[i] = (a[2*i]&mod_mask) + (((uint64_t)(a[2*i+1]&mod_mask))<<25);
        b64[i] = (b[2*i]&mod_mask) + (((uint64_t)(b[2*i+1]&mod_mask))<<25);
    }
    if (len%2 == 1) {
        a64[N2-1] = a[len-1] & mod_mask;
        b64[N2-1] = b[len-1] & mod_mask;
    }

    /* multiply a64 by b64 */
    uint16_t clen = 2 * N2;   /* double capacity for intermediate result */
    uint64_t c64[clen];
    memset(&c64, 0, clen*8);
    uint16_t overflow_ctr_start = (1<<(25-ntru_log2(mod_mask+1))) - 1;
    uint16_t overflow_ctr_rem = overflow_ctr_start;
    for (i=0; i<N2; i++) {
        uint64_t j;
        for (j=0; j<N2; j++) {
            uint64_t ck = a64[i] * b64[j];
            c64[i+j] += ck & mod_mask_64;
            c64[i+j+1] += ck >> 50;
            overflow_ctr_rem--;
            if (!overflow_ctr_rem) {
                uint16_t k;
                for (k=0; k<clen; k++)
                    c64[k] &= mod_mask_64;
                overflow_ctr_rem = overflow_ctr_start;
            }
        }
    }

    /* transform c64 into NtruIntPoly representation */
    memset(c, 0, 2*(2*len-1));
    uint16_t k = 0;
    for (i=0; i<clen; i++) {
        c[k] += c64[i];
        if (++k >= N)
            k = 0;
        c[k] += c64[i] >> 25;
        if (++k >= N)
            k = 0;
    }
}

void ntru_mult_karatsuba_64(int16_t *a, int16_t *b, int16_t *c, uint16_t len, uint16_t N, uint16_t mod_mask) {
    if (len < NTRU_KARATSUBA_THRESH_64)
        ntru_mult_int_64_base(a, b, c, len, N, mod_mask);
    else {
        uint16_t len2 = len / 2;
        int16_t z0[NTRU_INT_POLY_SIZE];
        int16_t z1[NTRU_INT_POLY_SIZE];
        int16_t z2[NTRU_INT_POLY_SIZE];

        /* z0, z2 */
        ntru_mult_karatsuba_64(a, b, z0, len2, N, mod_mask);
        ntru_mult_karatsuba_64(a+len2, b+len2, z2, len-len2, N, mod_mask);

        /* z1 */
        int16_t lh1[NTRU_INT_POLY_SIZE];
        int16_t lh2[NTRU_INT_POLY_SIZE];
        uint16_t i;
        for (i=0; i<len2; i++) {
            lh1[i] = a[i] + a[len2+i];
            lh2[i] = b[i] + b[len2+i];
        }
        if (len%2 != 0) {
            lh1[len-len2-1] = a[len-1];
            lh2[len-len2-1] = b[len-1];
        }
        ntru_mult_karatsuba_64(lh1, lh2, z1, len-len2, N, mod_mask);
        for (i=0; i<2*len2-1; i++)
            z1[i] -= z0[i];
        z1[len] = 0;
        for (i=0; i<2*(len-len2)-1; i++)
            z1[i] -= z2[i];

        /* c */
        memset(c, 0, NTRU_INT_POLY_SIZE*2);
        memcpy(c, z0, 2*(2*len2-1));   /* 2*len2-1 coefficients */
        uint16_t c_idx = len2;
        for (i=0; i<2*(len-len2)-1; i++) {
            c[c_idx] += z1[i];
            c_idx++;
            if (c_idx >= N)
                c_idx = 0;
        }
        c_idx = 2 * len2;
        if (c_idx >= N)
            c_idx = 0;
        for (i=0; i<2*(len-len2)-1; i++) {
            c[c_idx] += z2[i];
            c_idx++;
            if (c_idx >= N)
                c_idx = 0;
        }
    }
}

uint8_t ntru_mult_int_64(NtruIntPoly *a, NtruIntPoly *b, NtruIntPoly *c, uint16_t mod_mask) {
    uint16_t N = a->N;
    if (N != b->N)
        return 0;
    c->N = N;

    ntru_mult_karatsuba_64((int16_t*)&a->coeffs, (int16_t*)&b->coeffs, (int16_t*)&c->coeffs, N, N, mod_mask);
    ntru_mod_mask(c, mod_mask);

    return 1;
}

uint8_t ntru_mult_tern_32(NtruIntPoly *a, NtruTernPoly *b, NtruIntPoly *c, uint16_t mod_mask) {
    uint16_t N = a->N;
    if (N != b->N)
        return 0;
    c->N = N;
    memset(&c->coeffs, 0, N * sizeof c->coeffs[0]);

    uint32_t mod_mask_32 = mod_mask;
    mod_mask_32 += mod_mask_32 << 16;
    typedef uint32_t __attribute__((__may_alias__)) uint32_t_alias;

    /* make sure a.coeffs[i] <= mod_mask */
    ntru_mod_mask(a, mod_mask_32);

    uint16_t overflow_ctr_start = (1<<16)/(mod_mask+1) - 1;
    uint16_t overflow_ctr_rem = overflow_ctr_start;

    /* add coefficients that are multiplied by 1 */
    uint16_t i;
    for (i=0; i<b->num_ones; i++) {
        int16_t j;
        int16_t k = b->ones[i];
        uint16_t j_end = N-2<b->ones[i] ? 0 : N-2-b->ones[i];
        for (j=0; j<j_end; j+=2,k+=2)
            *((uint32_t_alias*)&c->coeffs[k]) += *((uint32_t_alias*)&a->coeffs[j]);
        for (; k<N; k++,j++)
            c->coeffs[k] += a->coeffs[j];
        for (k=0; j<N-2; j+=2,k+=2)
            *((uint32_t_alias*)&c->coeffs[k]) += *((uint32_t_alias*)&a->coeffs[j]);
        for (; j<N; j++,k++)
            c->coeffs[k] += a->coeffs[j];

        overflow_ctr_rem--;
        if (!overflow_ctr_rem) {
            ntru_mod_mask(c, mod_mask);
            overflow_ctr_rem = overflow_ctr_start;
        }
    }

    /* use inverse mask for subtraction */
    mod_mask_32 = ~mod_mask_32;
    for (i=0; i<N-2; i+=2)
        *((uint32_t_alias*)&c->coeffs[i]) |= mod_mask_32;
    for (; i<N; i++)
        c->coeffs[i] |= mod_mask_32;

    /* subtract coefficients that are multiplied by -1 */
    overflow_ctr_rem = overflow_ctr_start;
    for (i=0; i<b->num_neg_ones; i++) {
        int16_t j;
        int16_t k = b->neg_ones[i];
        uint16_t j_end = N-2<b->neg_ones[i] ? 0 : N-2-b->neg_ones[i];
        for (j=0; j<j_end; j+=2,k+=2)
            *((uint32_t_alias*)&c->coeffs[k]) -= *((uint32_t_alias*)&a->coeffs[j]);
        for (; k<N; k++,j++)
            c->coeffs[k] -= a->coeffs[j];
        for (k=0; j<N-2; j+=2,k+=2)
            *((uint32_t_alias*)&c->coeffs[k]) -= *((uint32_t_alias*)&a->coeffs[j]);
        for (; j<N; j++,k++)
            c->coeffs[k] -= a->coeffs[j];

        overflow_ctr_rem--;
        if (!overflow_ctr_rem) {
            for (j=0; j<N-2; j+=2)
                *((uint32_t_alias*)&c->coeffs[j]) |= mod_mask_32;
            for (; j<N; j++)
                c->coeffs[j] |= mod_mask_32;
            overflow_ctr_rem = overflow_ctr_start;
        }
    }

    ntru_mod_mask(c, mod_mask);
    return 1;
}

uint8_t ntru_mult_tern_64(NtruIntPoly *a, NtruTernPoly *b, NtruIntPoly *c, uint16_t mod_mask) {
    uint16_t N = a->N;
    if (N != b->N)
        return 0;
    memset(&c->coeffs, 0, N * sizeof c->coeffs[0]);
    c->N = N;

    uint64_t mod_mask_64 = mod_mask;
    mod_mask_64 += mod_mask_64 << 16;
    mod_mask_64 += mod_mask_64 << 32;
    typedef uint64_t __attribute__((__may_alias__)) uint64_t_alias;

    /* make sure a.coeffs[i] <= mod_mask */
    ntru_mod_mask(a, mod_mask);

    uint16_t overflow_ctr_start = (1<<16)/(mod_mask+1) - 1;
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
            ntru_mod_mask(c, mod_mask);
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

    ntru_mod_mask(c, mod_mask);
    return 1;
}

#ifndef NTRU_AVOID_HAMMING_WT_PATENT
uint8_t ntru_mult_prod(NtruIntPoly *a, NtruProdPoly *b, NtruIntPoly *c, uint16_t mod_mask) {
    uint16_t N = a->N;
    if (N != b->N)
        return 0;
    c->N = N;
    memset(&c->coeffs, 0, N * sizeof c->coeffs[0]);

    NtruIntPoly temp;
    ntru_mult_tern(a, &b->f1, &temp, mod_mask);
    ntru_mult_tern(&temp, &b->f2, c, mod_mask);
    NtruIntPoly f3a;
    ntru_mult_tern(a, &b->f3, &f3a, mod_mask);
    ntru_add(c, &f3a);

    ntru_mod_mask(c, mod_mask);
    return 1;
}
#endif   /* NTRU_AVOID_HAMMING_WT_PATENT */

uint8_t ntru_mult_priv(NtruPrivPoly *a, NtruIntPoly *b, NtruIntPoly *c, uint16_t mod_mask) {
#ifndef NTRU_AVOID_HAMMING_WT_PATENT
    if (a->prod_flag)
        return ntru_mult_prod(b, &a->poly.prod, c, mod_mask);
    else
#endif   /* NTRU_AVOID_HAMMING_WT_PATENT */
        return ntru_mult_tern(b, &a->poly.tern, c, mod_mask);
}

/** NtruPrivPoly to binary (coefficients reduced mod 2), 64 bit version */
void ntru_priv_to_mod2_64(NtruPrivPoly *a, uint64_t *b_coeffs64) {
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

/** NtruPrivPoly to binary (coefficients reduced mod 2), 32 bit version */
void ntru_priv_to_mod2_32(NtruPrivPoly *a, uint32_t *b_coeffs32) {
#ifndef NTRU_AVOID_HAMMING_WT_PATENT
    if (a->prod_flag) {
        NtruProdPoly *prod = &a->poly.prod;
        uint16_t N = prod->N;
        uint16_t N32 = (prod->N+31) / 32;
        memset(b_coeffs32, 0, N32*4);
        uint16_t i, j, bidx;
        for (i=0; i<prod->f1.num_ones; i++) {
            for (j=0; j<prod->f2.num_ones; j++) {
                bidx = prod->f1.ones[i] + prod->f2.ones[j];
                if (bidx >= N)
                    bidx -= N;
                b_coeffs32[bidx/32] ^= ((uint32_t)1) << (bidx%32);
            }
            for (j=0; j<prod->f2.num_neg_ones; j++) {
                bidx = prod->f1.ones[i] + prod->f2.neg_ones[j];
                if (bidx >= N)
                    bidx -= N;
                b_coeffs32[bidx/32] ^= ((uint32_t)1) << (bidx%32);
            }
        }
        for (i=0; i<prod->f1.num_neg_ones; i++) {
            for (j=0; j<prod->f2.num_ones; j++) {
                bidx = prod->f1.neg_ones[i] + prod->f2.ones[j];
                if (bidx >= N)
                    bidx -= N;
                b_coeffs32[bidx/32] ^= ((uint32_t)1) << (bidx%32);
            }
            for (j=0; j<prod->f2.num_neg_ones; j++) {
                bidx = prod->f1.neg_ones[i] + prod->f2.neg_ones[j];
                if (bidx >= N)
                    bidx -= N;
                b_coeffs32[bidx/32] ^= ((uint32_t)1) << (bidx%32);
            }
        }
        for (i=0; i<prod->f3.num_ones; i++) {
            uint16_t ai = prod->f3.ones[i];
            b_coeffs32[ai/32] ^= ((uint32_t)1) << (ai%32);
        }
        for (i=0; i<prod->f3.num_neg_ones; i++) {
            uint16_t ai = prod->f3.neg_ones[i];
            b_coeffs32[ai/32] ^= ((uint32_t)1) << (ai%32);
        }
    }
    else
#endif   /* NTRU_AVOID_HAMMING_WT_PATENT */
    {
        NtruTernPoly *tern = &a->poly.tern;
        uint16_t N32 = (tern->N+31) / 32;
        memset(b_coeffs32, 0, N32*4);
        uint16_t i;
        for (i=0; i<tern->num_ones; i++) {
            uint16_t ai = tern->ones[i];
            b_coeffs32[ai/32] ^= ((uint32_t)1) << (ai%32);
        }
        for (i=0; i<tern->num_neg_ones; i++) {
            uint16_t ai = tern->neg_ones[i];
            b_coeffs32[ai/32] ^= ((uint32_t)1) << (ai%32);
        }
    }
}

void ntru_to_arr_64(NtruIntPoly *p, uint16_t q, uint8_t *a) {
    uint16_t N = p->N;
    uint8_t log_q = ntru_log2(q);
    uint16_t enc_bytes = ntru_enc_len_Nq(N, q);
    uint16_t rem = enc_bytes % sizeof(uint64_t);
    uint16_t quo = enc_bytes / sizeof(uint64_t);
    uint16_t enc_last_int = rem ? quo : quo - 1;
    uint16_t enc_last_int_valid = rem ? rem : sizeof(uint64_t);
    uint64_t last = 0;

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
            if (a_idx == enc_last_int)
                last |= coeff << bit_idx;
            else
            a64[a_idx] |= coeff << bit_idx;
            bit_idx += log_q;
        }
        else {
            a64[a_idx] |= coeff << bit_idx;
            a_idx++;
            bit_idx += log_q - 64;

            if (a_idx == enc_last_int)
                last = coeff >> (log_q - bit_idx);
            else
            a64[a_idx] = coeff >> (log_q-bit_idx);
        }
    }

    /* reverse byte order on big-endian machines */
    uint16_t i;
    for (i = 0; i <= a_idx; i++)
    {
        if (i == enc_last_int) {
            last = htole64(last);
            memcpy(&a64[i], &last, enc_last_int_valid);
        }
        else
        a64[i] = htole64(a64[i]);
    }
}

void ntru_to_arr_32(NtruIntPoly *p, uint16_t q, uint8_t *a) {
    uint16_t N = p->N;
    uint8_t log_q = ntru_log2(q);
    uint16_t enc_bytes = ntru_enc_len_Nq(N, q);
    uint16_t rem = enc_bytes % sizeof(uint32_t);
    uint16_t quo = enc_bytes / sizeof(uint32_t);
    uint16_t enc_last_int = rem ? quo : quo - 1;
    uint16_t enc_last_int_valid = rem ? rem : sizeof(uint32_t);
    uint32_t last = 0;

    typedef uint32_t __attribute__((__may_alias__)) *uint32_t_alias;
    uint32_t *a32 = (uint32_t_alias)a;
    uint16_t a_idx = 0;   /* index into a32 */
    uint8_t bit_idx = 0;   /* next unused bit of a32[a_idx] */
    a32[0] = 0;
    uint16_t p_idx;
    uint32_t mod_mask = q - 1;
    for (p_idx=0; p_idx<N; p_idx++) {
        uint32_t coeff = p->coeffs[p_idx] & mod_mask;
        if (bit_idx < 32-log_q) {
            if (a_idx == enc_last_int)
                last |= coeff << bit_idx;
            else
            a32[a_idx] |= coeff << bit_idx;
            bit_idx += log_q;
        }
        else {
            a32[a_idx] |= coeff << bit_idx;
            a_idx++;
            bit_idx += log_q - 32;

            if (a_idx == enc_last_int)
                last = coeff >> (log_q - bit_idx);
            else
            a32[a_idx] = coeff >> (log_q-bit_idx);
        }
    }

    /* reverse byte order on big-endian machines */
    uint16_t i;
    for (i = 0; i <= a_idx; i++)
    {
        if (i == enc_last_int) {
            last = htole32(last);
            memcpy(&a32[i], &last, enc_last_int_valid);
        }
        else
        a32[i] = htole32(a32[i]);
    }
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

    uint8_t bits_per_coeff = ntru_log2(q);
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

void ntru_mod_64(NtruIntPoly *p, uint16_t mod_mask) {
    typedef uint64_t __attribute__((__may_alias__)) uint64_t_alias;
    uint64_t mod_mask_64 = mod_mask;
    mod_mask_64 += mod_mask_64 << 16;
    mod_mask_64 += mod_mask_64 << 32;
    uint16_t i;
    for (i=0; i<p->N; i+=4)
        *((uint64_t_alias*)&p->coeffs[i]) &= mod_mask_64;
}

void ntru_mod_32(NtruIntPoly *p, uint16_t mod_mask) {
    typedef uint32_t __attribute__((__may_alias__)) uint32_t_alias;
    uint32_t mod_mask_32 = mod_mask;
    mod_mask_32 += mod_mask_32 << 16;
    uint16_t i;
    for (i=0; i<p->N; i+=2)
        *((uint32_t_alias*)&p->coeffs[i]) &= mod_mask_32;
}

void ntru_mod3_standard(NtruIntPoly *p) {
    uint16_t i;
    for (i=0; i<p->N; i++) {
        int8_t c = p->coeffs[i] % 3;
        if (c == -2)
            c = 1;
        if (c == -1)
            c = 2;
        p->coeffs[i] = c;
    }
}

void ntru_mod3(NtruIntPoly *p) {
#ifdef NTRU_DETECT_SIMD
    if (__builtin_cpu_supports("avx2"))
        return ntru_mod3_avx2(p);
    else if (__builtin_cpu_supports("ssse3"))
        return ntru_mod3_sse(p);
    else
        return ntru_mod3_standard(p);
#else
#ifdef __AVX2__
    ntru_mod3_avx2(p);
#elif __SSSE3__
    ntru_mod3_sse(p);
#else
    ntru_mod3_standard(p);
#endif   /* __SSSE3__ */
#endif   /* NTRU_DETECT_SIMD */
}

void ntru_mod_center(NtruIntPoly *p, uint16_t modulus) {
    uint16_t m2 = modulus / 2;
    uint16_t mod_mask = modulus - 1;
    uint16_t i;
    for (i=0; i<p->N; i++) {
        uint16_t c = p->coeffs[i] & mod_mask;   // note that c is unsigned
        if (c > m2)
            c -= modulus;
        p->coeffs[i] = c;
    }
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

uint16_t ntru_deg_32(uint32_t *coeffs, uint16_t len) {
    uint16_t deg = 32*len - 1;
    len--;
    while (len>0 && coeffs[len]==0) {
        len--;
        deg -= 32;
    }
    while (coeffs[len]>>(deg%32)==0 && deg>0)
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
void ntru_lift_inverse(NtruPrivPoly *a, NtruIntPoly *Fq, uint16_t q) {
    NtruIntPoly temp1, temp2;
    uint32_t v = 2;
    while (v < q) {
        v *= v;

        /* temp1 = (1+3a)*Fq */
        ntru_mult_priv(a, Fq, &temp1, q-1);
        ntru_mult_fac(&temp1, 3);
        ntru_add(&temp1, Fq);

        ntru_neg_mod(&temp1, q);
        temp1.coeffs[0] += 2;
        memcpy(&temp2, Fq, sizeof *Fq);
        ntru_mult_int(&temp1, &temp2, Fq, q-1);
    }
}

uint8_t ntru_invert_32(NtruPrivPoly *a, uint16_t mod_mask, NtruIntPoly *Fq) {
    int16_t i;
#ifndef NTRU_AVOID_HAMMING_WT_PATENT
    uint16_t N = a->prod_flag ? a->poly.prod.N : a->poly.tern.N;
#else
    uint16_t N = a->poly.tern.N;
#endif   /* NTRU_AVOID_HAMMING_WT_PATENT */
    uint16_t k = 0;
    uint16_t N32 = (N+1+31) / 32;   /* #uint32_t's needed for N+1 coeffs */

    /* b = 1 */
    uint32_t b_coeffs32_arr[N32];
    uint32_t *b_coeffs32 = b_coeffs32_arr;
    memset(b_coeffs32+1, 0, (N32-1)*4);
    b_coeffs32[0] = 1;

    /* c = 0 */
    uint32_t c_coeffs32_arr[N32];
    uint32_t *c_coeffs32 = c_coeffs32_arr;
    memset(c_coeffs32, 0, N32*4);

    /* f=3a+1; skip multiplication by 3 because f=3f (mod 2) */
    uint32_t f_coeffs32_arr[N32];
    uint32_t *f_coeffs32 = f_coeffs32_arr;
    ntru_priv_to_mod2_32(a, f_coeffs32);
    f_coeffs32[0] ^= 1;

    /* g(x) = x^N − 1 */
    uint32_t g_coeffs32_arr[N32];
    uint32_t *g_coeffs32 = g_coeffs32_arr;
    memset(g_coeffs32, 0, N32*4);
    g_coeffs32[0] = 1;
    g_coeffs32[N/32] |= ((uint32_t)1) << (N%32);

    uint16_t deg_f = ntru_deg_32(f_coeffs32, N32);
    uint16_t deg_g = N;
    for (;;) {
        uint16_t num_zeros = 0;
        /* while f[0]==0 */
        while ((f_coeffs32[num_zeros/32]&(((uint32_t)1)<<(num_zeros%32)))==0 && num_zeros<=N)
            num_zeros++;
        if (num_zeros >= N)   /* not invertible */
            return 0;
        k += num_zeros;

        /* right-shift f, left-shift c num_zeros coefficients each */
        if (num_zeros >= 32) {
            memmove(c_coeffs32+num_zeros/32, c_coeffs32, N32*4-num_zeros/32*4);
            memset(c_coeffs32, 0, num_zeros/32*4);
            memmove(f_coeffs32, f_coeffs32+num_zeros/32, N32*4-num_zeros/32*4);
            memset(f_coeffs32+N32-num_zeros/32, 0, num_zeros/32*4);
            deg_f -= num_zeros / 32 * 32;
            num_zeros %= 32;
        }
        if (num_zeros > 0) {
            /* c(x) = c(x)*(x^num_zeros) */
            for (i=N32-1; i>0; i--) {
                c_coeffs32[i] <<= num_zeros;
                c_coeffs32[i] |= c_coeffs32[i-1] >> (32-num_zeros);
            }
            c_coeffs32[0] <<= num_zeros;
            /* f(x) = f(x)/(x^num_zeros) */
            for (i=1; i<N32; i++) {
                f_coeffs32[i-1] >>= num_zeros;
                f_coeffs32[i-1] |= f_coeffs32[i] << (32-num_zeros);
            }
            f_coeffs32[i-1] >>= num_zeros;
        }
        deg_f -= num_zeros;

        if (deg_f==0 && f_coeffs32[0]==1)   /* if f==1 */
            break;
        if (deg_f < deg_g) {
            /* exchange f and g */
            uint32_t *temp_coeffs = f_coeffs32;
            f_coeffs32 = g_coeffs32;
            g_coeffs32 = temp_coeffs;
            uint16_t temp = deg_f;
            deg_f = deg_g;
            deg_g = temp;
            /* exchange b and c */
            temp_coeffs = b_coeffs32;
            b_coeffs32 = c_coeffs32;
            c_coeffs32 = temp_coeffs;
        }
        ntru_add_mod2_32(f_coeffs32, g_coeffs32, N32);
        /* adding f+g may have lowered the degree of f */
        while (deg_f>0 && (f_coeffs32[deg_f/32]&(((uint32_t)1)<<(deg_f%32)))==0)
            deg_f--;
        ntru_add_mod2_32(b_coeffs32, c_coeffs32, N32);
    }

    if ((b_coeffs32[(N+1-1)/32]&(((uint32_t)1)<<((N+1-1)%32))) != 0)   /* if (b[N]!=0) */
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
        Fq->coeffs[j] = (b_coeffs32[i/32]>>(i%32)) & 1;   /* Fq->coeffs[j]=b[i] */
    }

    ntru_lift_inverse(a, Fq, mod_mask+1);

    return 1;
}

uint8_t ntru_invert_64(NtruPrivPoly *a, uint16_t mod_mask, NtruIntPoly *Fq) {
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
    ntru_priv_to_mod2_64(a, f_coeffs64);
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
            deg_f -= num_zeros / 64 * 64;
            num_zeros %= 64;
        }
        if (num_zeros > 0) {
            int16_t i;
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
        ntru_add_mod2_64(f_coeffs64, g_coeffs64, N64);
        /* adding f+g may have lowered the degree of f */
        while (deg_f>0 && (f_coeffs64[deg_f/64]&(((uint64_t)1)<<(deg_f%64)))==0)
            deg_f--;
        ntru_add_mod2_64(b_coeffs64, c_coeffs64, N64);
    }

    if ((b_coeffs64[(N+1-1)/64]&(((uint64_t)1)<<((N+1-1)%64))) != 0)   /* if (b[N]!=0) */
        return 0;

    /* Fq(x) = x^(N-k) * b(x) */
    memset(&Fq->coeffs, 0, N * sizeof Fq->coeffs[0]);
    Fq->N = N;
    int16_t j = 0;
    while (k >= N)
        k -= N;
    int16_t i;
    for (i=N-1; i>=0; i--) {
        j = i - k;
        if (j < 0)
            j += N;
        Fq->coeffs[j] = (b_coeffs64[i/64]>>(i%64)) & 1;   /* Fq->coeffs[j]=b[i] */
    }

    ntru_lift_inverse(a, Fq, mod_mask+1);

    return 1;
}

uint8_t (*ntru_invert)(NtruPrivPoly *a, uint16_t mod_mask, NtruIntPoly *Fq);

void ntru_set_optimized_impl_poly() {
#ifdef NTRU_DETECT_SIMD
    if (__builtin_cpu_supports("avx2")) {
        ntru_mult_int = ntru_mult_int_avx2;
        ntru_mult_tern = ntru_mult_tern_avx2;
        ntru_to_arr = ntru_to_arr_sse;
        ntru_mod_mask = ntru_mod_avx2;
    }
    else if (__builtin_cpu_supports("ssse3")) {
        ntru_mult_int = ntru_mult_int_sse;
        ntru_mult_tern = ntru_mult_tern_sse;
        ntru_to_arr = ntru_to_arr_sse;
        ntru_mod_mask = ntru_mod_sse;
    }
    else if (sizeof(void*) >= 8) {   /* 64-bit arch */
        ntru_mult_int = ntru_mult_int_64;
        ntru_mult_tern = ntru_mult_tern_64;
        ntru_to_arr = ntru_to_arr_64;
        ntru_mod_mask = ntru_mod_64;
    }
    else {
        ntru_mult_int = ntru_mult_int_16;
        ntru_mult_tern = ntru_mult_tern_32;
        ntru_to_arr = ntru_to_arr_32;
        ntru_mod_mask = ntru_mod_32;
    }

    if (sizeof(void*) >= 8)   /* 64-bit arch */
        ntru_invert = ntru_invert_64;
    else
        ntru_invert = ntru_invert_32;

#else

#ifdef __AVX2__
    ntru_mult_int = ntru_mult_int_avx2;
    ntru_mult_tern = ntru_mult_tern_avx2;
    ntru_to_arr = ntru_to_arr_sse;
    ntru_mod_mask = ntru_mod_avx2;
#elif __SSSE3__
    ntru_mult_int = ntru_mult_int_sse;
    ntru_mult_tern = ntru_mult_tern_sse;
    ntru_to_arr = ntru_to_arr_sse;
    ntru_mod_mask = ntru_mod_sse;
#elif _LP64
    ntru_mult_int = ntru_mult_int_64;
    ntru_mult_tern = ntru_mult_tern_64;
    ntru_to_arr = ntru_to_arr_64;
    ntru_mod_mask = ntru_mod_64;
#else
    ntru_mult_int = ntru_mult_int_16;
    ntru_mult_tern = ntru_mult_tern_32;
    ntru_to_arr = ntru_to_arr_32;
    ntru_mod_mask = ntru_mod_32;
#endif

#if _LP64
    ntru_invert = ntru_invert_64;
#else
    ntru_invert = ntru_invert_32;
#endif
#endif   /* NTRU_DETECT_SIMD */
}
