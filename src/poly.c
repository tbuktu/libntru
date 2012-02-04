#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include "poly.h"

int ntru_num_bits(int n) {
    int b = 1;
    while (n >>= 1)
        b++;
    return b;
}

int ntru_rand_tern(int N, int num_ones, int num_neg_ones, NtruTernPoly *poly, int (*rng)(unsigned[], int)) {
    int i;

    int rand_len = num_ones + num_neg_ones + 10;
    unsigned rand_data[rand_len];   /* 10 more to avoid re-reading /dev/random for up to 10 collisions */
    if (!rng(rand_data, rand_len))
        return 0;
    int r_idx = 0;   /* index into rand_data */

    int bits = ntru_num_bits(N);
    for (i=0; i<num_ones; i++) {
        int r = rand_data[r_idx] >> (8*sizeof r - bits);   /* 0 <= r < 2^bits */
        r_idx++;
        poly->ones[i] = r;
    }

    i = 0;
    while (i < num_neg_ones) {
        int r = rand_data[r_idx] >> (8*sizeof r - bits);   /* 0 <= r < 2^bits */
        r_idx++;
        if (poly->ones[r] == 0) {
            poly->neg_ones[i] = r;
            i++;
        }
        /* refill rand_data if we run out */
        else if (r_idx >= sizeof rand_data) {
            if (!rng(rand_data, rand_len))
                return 0;
            r_idx = 0;
        }
    }

    poly->N = 1<<bits;
    poly->num_ones = num_ones;
    poly->num_neg_ones = num_neg_ones;

    return 1;
}

void ntru_rand_prod(int N, int df1, int df2, int df3_ones, int df3_neg_ones, NtruProdPoly *poly, int (*rng)(unsigned[], int)) {
    poly->N = N;
    ntru_rand_tern(N, df1, df1, &poly->f1, rng);
    ntru_rand_tern(N, df2, df2, &poly->f2, rng);
    ntru_rand_tern(N, df3_ones, df3_neg_ones, &poly->f3, rng);
}

void ntru_add_tern(NtruIntPoly *a, NtruTernPoly *b) {
    int i;
    for (i=0; i<b->num_ones; i++)
        a->coeffs[b->ones[i]]++;
    for (i=0; i<b->num_neg_ones; i++)
        a->coeffs[b->neg_ones[i]]--;
}

void ntru_add_int(NtruIntPoly *a, NtruIntPoly *b) {
    int i;
    for (i=0; i<b->N; i++)
        a->coeffs[i] += b->coeffs[i];
}

void ntru_add_int_mod(NtruIntPoly *a, NtruIntPoly *b, int modulus) {
    int i;
    for (i=0; i<b->N; i++)
        a->coeffs[i] = (a->coeffs[i]+b->coeffs[i]) % modulus;
}

void ntru_sub_int_mod(NtruIntPoly *a, NtruIntPoly *b, int modulus) {
    int i;
    for (i=0; i<b->N; i++)
        a->coeffs[i] = (a->coeffs[i]-b->coeffs[i]) % modulus;
}

int ntru_mult_int(NtruIntPoly *a, NtruIntPoly *b, NtruIntPoly *c) {
    int N = a->N;
    if (N != b->N)
        return 0;
    c->N = N;

    int i, k;
    for (k=0; k<N; k++)
        for (i=0; i<N; i++)
            c->coeffs[k] += b->coeffs[i] * a->coeffs[(N+k-i)%N];

    return 1;
}

int ntru_mult_int_mod(NtruIntPoly *a, NtruIntPoly *b, NtruIntPoly *c, int modulus) {
    int N = a->N;
    if (N != b->N)
        return 0;
    c->N = N;

    int k;
    for (k=0; k<N; k++) {
        int ck = 0;
        int i;
        for (i=0; i<N; i++)
            ck += b->coeffs[i] * a->coeffs[(N+k-i)%N];
        c->coeffs[k] = ck % modulus;
    }

    return 1;
}

int ntru_mult_tern(NtruIntPoly *a, NtruTernPoly *b, NtruIntPoly *c) {
    int N = a->N;
    if (N != b->N)
        return 0;
    c->N = N;
    
    int i;
    for (i=0; i<b->num_ones; i++) {
        int j = N - 1 - b->ones[i];
        int k;
        for(k=N-1; k>=0; k--) {
            c->coeffs[k] += a->coeffs[j];
            j--;
            if (j < 0)
                j = N - 1;
        }
    }
    
    for (i=0; i<b->num_neg_ones; i++) {
        int j = N - 1 - b->neg_ones[i];
        int k;
        for(k=N-1; k>=0; k--) {
            c->coeffs[k] -= a->coeffs[j];
            j--;
            if (j < 0)
                j = N - 1;
        }
    }

    return 1;
}

void ntru_tern_to_int(NtruTernPoly *a, NtruIntPoly *b) {
    memset(&b->coeffs, 0, a->N);
    int i;
    for (i=0; i<a->num_ones; i++)
        b->coeffs[a->ones[i]] = 1;
    for (i=0; i<a->num_neg_ones; i++)
        b->coeffs[a->neg_ones[i]] = -1;

    b->N = a->N;
}

void ntru_prod_to_int(NtruProdPoly *a, NtruIntPoly *b) {
    NtruIntPoly c;
    ntru_tern_to_int(&a->f1, &c);
    ntru_mult_tern(&c, &a->f2, b);
    ntru_add_tern(b, &a->f3);
}

void ntru_mult_fac(NtruIntPoly *a, int factor) {
    int i;
    for (i=0; i<a->N; i++)
        a->coeffs[i] *= factor;
}

void ntru_mult_2(NtruIntPoly *a, int modulus) {
    int i;
    for (i=0; i<a->N; i++)
        a->coeffs[i] = (a->coeffs[i]*2) % modulus;
}

NtruIntPoly *ntru_zero_poly(int n) {
    NtruIntPoly *poly = calloc(1, sizeof *poly);
    if (poly)
        poly->N = n;
    return poly;
}

NtruIntPoly *ntru_clone(NtruIntPoly *a) {
    NtruIntPoly *b = malloc(sizeof *a);
    memcpy(b, a, sizeof *a);
    return b;
}

void ntru_mod(NtruIntPoly *p, int modulus) {
    int i;
    if (modulus == 2048)
        for (i=0; i<p->N; i++)
            p->coeffs[i] &= 2047;
    else
        for (i=0; i<p->N; i++)
            p->coeffs[i] %= modulus;
}

void ntru_mod2(NtruIntPoly *p) {
    int i;
    for (i=0; i<p->N; i++)
        p->coeffs[i] &= 1;
}

int ntru_equals0(NtruIntPoly *p) {
    int i;
    for (i=0; i<p->N; i++)
        if (p->coeffs[i] != 0)
            return 0;
    return 1;
}

int ntru_equals1(NtruIntPoly *p) {
    int i;
    for (i=1; i<p->N; i++)
        if (p->coeffs[i] != 0)
            return 0;
    return p->coeffs[0] == 1;
}

int ntru_deg(NtruIntPoly *p) {
    int deg = p->N - 1;
    while (deg>0 && p->coeffs[deg]==0)
        deg--;
    return deg;
}

void ntru_mod2_to_modq(NtruIntPoly *a, NtruIntPoly *Fq, int q) {
    int v = 2;
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

int ntru_invert(NtruIntPoly *a, int q, NtruIntPoly *Fq) {
    int i;
    int N = a->N;
    int k = 0;
    NtruIntPoly *b = ntru_zero_poly(N+1);
    b->coeffs[0] = 1;
    NtruIntPoly *c = ntru_zero_poly(N+1);
    NtruIntPoly *f = ntru_clone(a);
    f->N++;   /* add one coefficient for a total of N+1 */
    ntru_mod2(f);
    // set g(x) = x^N − 1
    NtruIntPoly *g = ntru_zero_poly(N+1);
    g->coeffs[0] = 1;
    g->coeffs[N] = 1;
    for (;;) {
        while (f->coeffs[0] == 0) {
            for (i=1; i<=N; i++) {
                f->coeffs[i-1] = f->coeffs[i];   // f(x) = f(x) / x
                c->coeffs[N+1-i] = c->coeffs[N-i];   // c(x) = c(x) * x
            }
            f->coeffs[N] = 0;
            c->coeffs[0] = 0;
            k++;
            if (ntru_equals0(f))
                return 0;   // not invertible
        }
        if (ntru_equals1(f))
            break;
        if (ntru_deg(f) < ntru_deg(g)) {
            // exchange f and g
            NtruIntPoly *temp = f;
            f = g;
            g = temp;
            // exchange b and c
            temp = b;
            b = c;
            c = temp;
        }
        ntru_add_int_mod(f, g, 2);
        ntru_add_int_mod(b, c, 2);
    }
    
    if (b->coeffs[N] != 0)
        return 0;
    // Fq(x) = x^(N-k) * b(x)
    memset(&Fq->coeffs, 0, N);
    Fq->N = N;
    int j = 0;
    k %= N;
    for (i=N-1; i>=0; i--) {
        j = i - k;
        if (j < 0)
            j += N;
        Fq->coeffs[j] = b->coeffs[i];
    }

    free(b);
    free(c);
    free(f);
    free(g);

    ntru_mod2_to_modq(a, Fq, q);
    return 1;
}

int dev_random(unsigned rand_data[], int len) {
    int rand_fd = open("/dev/random", O_RDONLY);
    if (rand_fd < 0)
        return 0;
    int tot_bytes = 0;
    unsigned len_bytes = len * (sizeof rand_data[0]);
    while (tot_bytes < len_bytes) {
        int bytes_read = read(rand_fd, ((char*)rand_data)+tot_bytes, len_bytes-tot_bytes);
        if (bytes_read <= 0)
            return 0;
        tot_bytes += bytes_read;
    }
    close(rand_fd);
    return tot_bytes == len_bytes;
}

int dev_urandom(unsigned rand_data[], int len) {
    int rand_fd = open("/dev/urandom", O_RDONLY);
    if (rand_fd < 0)
        return 0;
    int bytes_read = read(rand_fd, rand_data, len * sizeof *rand_data);
    close(rand_fd);
    return bytes_read == len * sizeof rand_data[0];
}
