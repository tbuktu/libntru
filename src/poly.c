#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#ifdef WIN32
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <Wincrypt.h>
#endif
#include "poly.h"
#include "err.h"

int ntru_num_bits(int n) {
    int b = 1;
    while (n >>= 1)
        b++;
    return b;
}

int ntru_rand_tern(int N, int num_ones, int num_neg_ones, NtruTernPoly *poly, int (*rng)(unsigned[], int)) {
    int coeffs[N];
    memset(&coeffs, 0, N * sizeof coeffs[0]);

    int rand_len = num_ones + num_neg_ones + 10;
    unsigned rand_data[rand_len];   /* 10 more to avoid re-reading /dev/random for up to 10 collisions */
    if (!rng(rand_data, rand_len))
        return 0;
    int r_idx = 0;   /* index into rand_data */

    int bits = ntru_num_bits(N);
    int i = 0;
    while (i < num_ones) {
        int r = rand_data[r_idx] >> (8*sizeof r - bits);   /* 0 <= r < 2^bits */
        r_idx++;
        if (r<N && !coeffs[r]) {
            poly->ones[i] = r;
            coeffs[r] = 1;
            i++;
        }
        /* refill rand_data if we run out */
        else if (r_idx >= rand_len) {
            if (!rng(rand_data, rand_len))
                return 0;
            r_idx = 0;
        }
    }

    i = 0;
    while (i < num_neg_ones) {
        int r = rand_data[r_idx] >> (8*sizeof r - bits);   /* 0 <= r < 2^bits */
        r_idx++;
        if (r<N && !coeffs[r]) {
            poly->neg_ones[i] = r;
            coeffs[r] = -1;
            i++;
        }
        /* refill rand_data if we run out */
        else if (r_idx >= sizeof rand_data) {
            if (!rng(rand_data, rand_len))
                return 0;
            r_idx = 0;
        }
    }

    poly->N = N;
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

void ntru_sub_int(NtruIntPoly *a, NtruIntPoly *b) {
    int i;
    for (i=0; i<b->N; i++)
        a->coeffs[i] -= b->coeffs[i];
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
    for (k=0; k<N; k++) {
        int ck = 0;
        for (i=0; i<N; i++)
            ck += b->coeffs[i] * a->coeffs[(N+k-i)%N];
        c->coeffs[k] = ck;
    }

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
    memset(&c->coeffs, 0, N * sizeof c->coeffs[0]);

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

int ntru_mult_prod(NtruIntPoly *a, NtruProdPoly *b, NtruIntPoly *c) {
    int N = a->N;
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

void ntru_tern_to_int(NtruTernPoly *a, NtruIntPoly *b) {
    memset(&b->coeffs, 0, a->N * sizeof b->coeffs[0]);
    int i;
    for (i=0; i<a->num_ones; i++)
        b->coeffs[a->ones[i]] = 1;
    for (i=0; i<a->num_neg_ones; i++)
        b->coeffs[a->neg_ones[i]] = -1;

    b->N = a->N;
}

void ntru_prod_to_int(NtruProdPoly *a, NtruIntPoly *b) {
    memset(&b->coeffs, 0, a->N * sizeof b->coeffs[0]);
    b->N = a->N;
    NtruIntPoly c;
    ntru_tern_to_int(&a->f1, &c);
    ntru_mult_tern(&c, &a->f2, b);
    ntru_add_tern(b, &a->f3);
}

void ntru_to_arr(NtruIntPoly *p, int q, char *a) {
    int bits_coeff = 0;
    while (q > 1) {
        q /= 2;
        bits_coeff++;
    }

    int bit_idx = 0;
    int byte_idx = 0;
    int i, j;
    a[0] = 0;
    for (i=0; i<p->N; i++)
        for (j=0; j<bits_coeff; j++) {
            int curr_bit = (p->coeffs[i] >> j) & 1;
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

void ntru_to_arr4(NtruIntPoly *p, char *arr) {
    int i = 0;
    while (i < p->N-3) {
        int c0 = p->coeffs[i] & 3;
        int c1 = p->coeffs[i+1] & 3;
        int c2 = p->coeffs[i+2] & 3;
        int c3 = p->coeffs[i+3] & 3;
        int d = c0 + (c1<<2) + (c2<<4) + (c3<<6);
        arr[i/4] = d;
        i += 4;
    }

    /* handle the last 0 to 3 coefficients */
    if (i >= p->N)
        return;
    int last = i / 4;
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

void ntru_from_arr(char *arr, int N, int q, NtruIntPoly *p) {
    p->N = N;
    memset(&p->coeffs, 0, N * sizeof p->coeffs[0]);

    int bits_per_coeff = 0;
    while (q > 1) {
        q /= 2;
        bits_per_coeff++;
    }

    int mask = 0xFFFFFFFF >> (32-bits_per_coeff);   /* for truncating values to bitsPerCoeff bits */
    int byte_idx = 0;
    int bit_idx = 0;   /* next bit in arr[byte_idx] */
    unsigned int coeff_buf = 0;   /* contains (bit_idx) bits */
    int coeff_bits = 0;   /* length of coeffBuf */
    int coeff_idx = 0;   /* index into coeffs */
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

void ntru_mod(NtruIntPoly *p, int modulus) {
    int i;
    if (modulus == 2048)
        for (i=0; i<p->N; i++)
            p->coeffs[i] &= 2047;
    else
        for (i=0; i<p->N; i++)
            p->coeffs[i] %= modulus;
}

void ntru_mod3(NtruIntPoly *p) {
    int i;
    for (i=0; i<p->N; i++) {
        int c = p->coeffs[i] % 3;
        if (c > 1)
            c = -1;
        if (c < -1)
            c = 1;
        p->coeffs[i] = c;
    }
}

void ntru_mod_center(NtruIntPoly *p, int modulus) {
    int i;
    if (modulus == 2048)
        for (i=0; i<p->N; i++) {
            int c = p->coeffs[i] & 2047;
            if (c & 1024)
                c -= 2048;
            p->coeffs[i] = c;
        }
    else {
        int m2 = modulus / 2;
        for (i=0; i<p->N; i++) {
            int c = p->coeffs[i] % modulus;
            if (c < -m2)
                c += modulus;
            if (c > m2)
                c -= modulus;
            p->coeffs[i] = c;
        }
    }
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

int ntru_equals_int(NtruIntPoly *a, NtruIntPoly *b) {
    if (a->N != b->N)
        return 0;

    int i;
    for (i=0; i<a->N; i++)
        if (a->coeffs[i] != b->coeffs[i])
            return 0;

    return 1;
}

int ntru_deg(NtruIntPoly *p) {
    int deg = p->N - 1;
    while (deg>0 && p->coeffs[deg]==0)
        deg--;
    return deg;
}

int ntru_count(NtruIntPoly *p, int value) {
    int count = 0;
    int i;
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
    int i;
    for (i=0; i<p->N; i++)
        p->coeffs[i] = 0;
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
    int invertible;
    int i;
    int N = a->N;
    int k = 0;
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
        ntru_add_int_mod(f, g, 2);
        ntru_add_int_mod(b, c, 2);
    }

    if (b->coeffs[N] != 0) {
        invertible = 0;
        goto done;
    }
    invertible = 1;

    /* Fq(x) = x^(N-k) * b(x) */
    memset(&Fq->coeffs, 0, N * sizeof Fq->coeffs[0]);
    Fq->N = N;
    int j = 0;
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

int sum_coeffs(NtruIntPoly *a) {
    int sum = 0;
    int i;
    for (i=1; i<a->N; i++)
        sum += a->coeffs[i];
    return sum;
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

#ifdef WIN32
int dev_urandom(unsigned rand_data[], int len) {
	static HCRYPTPROV hCryptProv = NULL;
	if (hCryptProv == NULL) {
        int result = CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, 0);
        if (!result) {
            if (GetLastError() == NTE_BAD_KEYSET)   // see http://support.microsoft.com/kb/238187
                result = CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_NEWKEYSET);
            if (!result)
	            return NTRU_ERR_PRNG;
        }
    }
	return CryptGenRandom(hCryptProv, len * sizeof *rand_data, rand_data);
}
#else
int dev_urandom(unsigned rand_data[], int len) {
    int rand_fd = open("/dev/urandom", O_RDONLY);
    if (rand_fd < 0)
        return 0;
    int bytes_read = read(rand_fd, rand_data, len * sizeof *rand_data);
    close(rand_fd);
    return bytes_read == len * sizeof rand_data[0];
}
#endif
