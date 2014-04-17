#include <stdlib.h>
#include <string.h>
#include "poly.h"
#include "rand.h"
#include "err.h"

uint8_t ntru_num_bits(uint16_t n) {
    uint8_t b = 1;
    while (n >>= 1)
        b++;
    return b;
}

uint8_t ntru_rand_tern(uint16_t N, uint16_t num_ones, uint16_t num_neg_ones, NtruTernPoly *poly, uint8_t (*rng)(uint8_t[], uint16_t, NtruRandContext*), NtruRandContext *rand_ctx) {
    int16_t coeffs[N];
    memset(&coeffs, 0, N * sizeof coeffs[0]);

    uint16_t rand_len = num_ones + num_neg_ones + 10;   /* 10 more to avoid calling rng() again for up to 10 collisions */
    uint16_t rand_data[rand_len*2];
    if (!rng((uint8_t*)rand_data, rand_len*2, rand_ctx))
        return 0;
    uint16_t r_idx = 0;   /* index into rand_data */

    uint16_t bits = ntru_num_bits(N);
    uint16_t i = 0;
    while (i < num_ones) {
        uint16_t r = rand_data[r_idx] >> (8*sizeof r - bits);   /* 0 <= r < 2^bits */
        r_idx++;
        /* refill rand_data if we run out */
        if (r_idx >= rand_len) {
            if (!rng((uint8_t*)rand_data, rand_len*2, rand_ctx))
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
            if (!rng((uint8_t*)rand_data, rand_len*2, rand_ctx))
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
uint8_t ntru_rand_prod(uint16_t N, uint16_t df1, uint16_t df2, uint16_t df3_ones, uint16_t df3_neg_ones, NtruProdPoly *poly, uint8_t (*rng)(uint8_t[], uint16_t, NtruRandContext*), NtruRandContext *rand_ctx) {
    poly->N = N;
    uint8_t result = ntru_rand_tern(N, df1, df1, &poly->f1, rng, rand_ctx);
    result &= ntru_rand_tern(N, df2, df2, &poly->f2, rng, rand_ctx);
    result &= ntru_rand_tern(N, df3_ones, df3_neg_ones, &poly->f3, rng, rand_ctx);
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

void ntru_sub_int(NtruIntPoly *a, NtruIntPoly *b) {
    uint16_t i;
    for (i=0; i<b->N; i++)
        a->coeffs[i] -= b->coeffs[i];
}

void ntru_sub_int_mod(NtruIntPoly *a, NtruIntPoly *b, uint16_t modulus) {
    uint16_t i;
    for (i=0; i<b->N; i++)
        a->coeffs[i] = (a->coeffs[i]-b->coeffs[i]) % modulus;
}

uint8_t ntru_mult_int_mod(NtruIntPoly *a, NtruIntPoly *b, NtruIntPoly *c, uint16_t modulus) {
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

uint8_t ntru_mult_tern(NtruIntPoly *a, NtruTernPoly *b, NtruIntPoly *c) {
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

    return 1;
}

#ifndef NTRU_AVOID_HAMMING_WT_PATENT
uint8_t ntru_mult_prod(NtruIntPoly *a, NtruProdPoly *b, NtruIntPoly *c) {
    uint16_t N = a->N;
    if (N != b->N)
        return 0;
    c->N = N;
    memset(&c->coeffs, 0, N * sizeof c->coeffs[0]);

    NtruIntPoly temp;
    ntru_mult_tern(a, &b->f1, &temp);
    ntru_mult_tern(&temp, &b->f2, c);
    NtruIntPoly f3a;
    ntru_mult_tern(a, &b->f3, &f3a);
    ntru_add_int(c, &f3a);

    return 1;
}
#endif   /* NTRU_AVOID_HAMMING_WT_PATENT */

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
void ntru_prod_to_int(NtruProdPoly *a, NtruIntPoly *b) {
    memset(&b->coeffs, 0, a->N * sizeof b->coeffs[0]);
    b->N = a->N;
    NtruIntPoly c;
    ntru_tern_to_int(&a->f1, &c);
    ntru_mult_tern(&c, &a->f2, b);
    ntru_add_tern(b, &a->f3);
}
#endif   /* NTRU_AVOID_HAMMING_WT_PATENT */

void ntru_to_arr(NtruIntPoly *p, uint16_t q, uint8_t *a) {
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

void ntru_mod(NtruIntPoly *p, uint16_t modulus) {
    uint16_t i;
    if (modulus == 2048)
        for (i=0; i<p->N; i++)
            p->coeffs[i] &= 2047;
    else
        for (i=0; i<p->N; i++)
            p->coeffs[i] %= modulus;
}

void ntru_mod3(NtruIntPoly *p) {
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

uint16_t ntru_count(NtruIntPoly *p, int16_t value) {
    uint16_t count = 0;
    uint16_t i;
    for (i=0; i<p->N; i++)
        if (p->coeffs[i] == value)
            count++;
    return count;
}

void ntru_clear_tern(NtruTernPoly *p) {
    memset(&p->ones, 0, p->num_ones * sizeof p->ones[0]);
    memset(&p->neg_ones, 0, p->num_neg_ones * sizeof p->neg_ones[0]);
}

void ntru_clear_int(NtruIntPoly *p) {
    uint16_t i;
    for (i=0; i<p->N; i++)
        p->coeffs[i] = 0;
}

void ntru_mod2_to_modq(NtruIntPoly *a, NtruIntPoly *Fq, uint16_t q) {
    uint16_t v = 2;
    NtruIntPoly temp, temp2, temp3;
    while (v < q) {
        v *= 2;
        memcpy(&temp, Fq, sizeof *Fq);
        ntru_mult_2(&temp, v);
        ntru_mult_int_mod(Fq, a, &temp2, v);
        ntru_mult_int_mod(&temp2, Fq, &temp3, v);
        ntru_sub_int_mod(&temp, &temp3, v);
        memcpy(Fq, &temp, sizeof temp);
    }
}

uint8_t ntru_invert(NtruIntPoly *a, uint16_t q, NtruIntPoly *Fq) {
    uint8_t invertible;
    int16_t i;
    uint16_t N = a->N;
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
    NtruIntPoly *f = ntru_clone(a);
    if (!f) {
        free(b);
        free(c);
        return NTRU_ERR_OUT_OF_MEMORY;
    }
    f->coeffs[f->N] = 0;   /* index N wasn't cloned */
    f->N++;   /* add one coefficient for a total of N+1 */
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

uint8_t ntru_is_invertible_pow2(NtruIntPoly *a) {
    uint8_t invertible;
    uint16_t i;
    uint16_t N = a->N;
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
    NtruIntPoly *f = ntru_clone(a);
    if (!f) {
        free(b);
        free(c);
        return NTRU_ERR_OUT_OF_MEMORY;
    }
    f->coeffs[f->N] = 0;   /* index N wasn't cloned */
    f->N++;   /* add one coefficient for a total of N+1 */
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

    invertible = b->coeffs[N] == 0;

done:
    free(b);
    free(c);
    free(f);
    free(g);

    return invertible;
}

int32_t ntru_sum_coeffs(NtruIntPoly *a) {
    int16_t sum = 0;
    uint16_t i;
    for (i=1; i<a->N; i++)
        sum += a->coeffs[i];
    return sum;
}
