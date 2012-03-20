#include <stdlib.h>
#include <string.h>
#include "ntruencrypt.h"
#include "poly.h"
#include "idxgen.h"
#include "mgf.h"
#include "err.h"

const int COEFF1_TABLE[] = {0, 0, 0, 1, 1, 1, -1, -1};
const int COEFF2_TABLE[] = {0, 1, -1, 0, 1, -1, 0, 1};
const int BIT1_TABLE[] = {1, 1, 1, 0, 0, 0, 1, 0, 1};
const int BIT2_TABLE[] = {1, 1, 1, 1, 0, 0, 0, 1, 0};
const int BIT3_TABLE[] = {1, 0, 1, 0, 0, 1, 1, 1, 0};

int ntru_gen_key_pair(struct NtruEncParams *params, NtruEncKeyPair *kp, int (*rng)(unsigned[], int)) {
    int N = params->N;
    int q = params->q;
    int df1 = params->df1;
    int df2 = params->df2;
    int df3 = params->df3;

    NtruProdPoly t;
    NtruIntPoly fq;

    /* choose a random f that is invertible mod q */
    NtruIntPoly f;
    for (;;) {
        /* choose random t, calculate f=3t+1 */
        ntru_rand_prod(N, df1, df2, df3, df3, &t, rng);
        ntru_prod_to_int(&t, &f);
        ntru_mult_fac(&f, 3);
        f.coeffs[0] += 1;

        if (ntru_invert(&f, q, &fq))
            break;
    }

    /* by the choice of t, f is always invertible mod 3 and fp=1 */
    NtruIntPoly fp = {N, {0}};
    fp.coeffs[0] = 1;

    /* choose a random g that is invertible mod q */
    NtruTernPoly g;
    NtruIntPoly gq;
    int dg = N / 3;
    for (;;) {
        if (!ntru_rand_tern(N, dg, dg-1, &g, rng))
            return 0;
        NtruIntPoly g_int;
        ntru_tern_to_int(&g, &g_int);
        if (ntru_invert(&g_int, q, &gq))
            break;
    }

    NtruIntPoly h;
    if (!ntru_mult_tern(&fq, &g, &h))
        return 0;
    ntru_mult_fac(&h, 3);
    ntru_mod(&h, q);

    ntru_clear_tern(&g);
    ntru_clear_int(&fq);

    NtruEncPrivKey priv = {q, t};
    kp->priv = priv;
    NtruEncPubKey pub = {q, h};
    kp->pub = pub;

    return 1;
}

/**
 * @brief Char array to ternary polynomial
 *
 * Decodes a char array encoded with ntru_to_sves() back to a polynomial with N
 * coefficients between -1 and 1.
 * Ignores any excess bytes.
 * See P1363.1 section 9.2.2.
 *
 * @param M an encoded ternary polynomial
 * @param M_len number of elements in M
 * @param N number of coefficients to generate
 * @param poly output parameter; pointer to write the polynomial to
 */
void ntru_from_sves(char *M, int M_len, int N, NtruIntPoly *poly) {
    poly->N = N;

    int coeff_idx = 0;
    int bit_idx;
    for (bit_idx=0; bit_idx<M_len*8; ) {
        int bit1 = get_bit(M, bit_idx++);
        int bit2 = get_bit(M, bit_idx++);
        int bit3 = get_bit(M, bit_idx++);
        int tbl_idx = bit1*4 + bit2*2 + bit3;
        poly->coeffs[coeff_idx++] = COEFF1_TABLE[tbl_idx];
        poly->coeffs[coeff_idx++] = COEFF2_TABLE[tbl_idx];

        /* ignore bytes that can't fit */
        if (coeff_idx > N-2)
            break;
    }
}

/**
 * @brief Ternary polynomial to char array
 *
 * Encodes a polynomial whose elements are between -1 and 1, to a char array.
 * The (2*i)-th coefficient and the (2*i+1)-th coefficient must not both equal
 * -1 for any integer i, so this method is only safe to use with arrays
 * produced by ntru_from_sves().
 * See P1363.1 section 9.2.3.
 *
 * @param poly a ternary polynomial
 * @param data output parameter; must accommodate ceil(num_bits/8) bytes
 * @return 0 for success, 1 for illegal encoding
 */
int ntru_to_sves(NtruIntPoly *poly, char *data) {
    int N = poly->N;

    int num_bits = (N*3+1) / 2;
    memset(data, 0, (num_bits+7)/8);

    int bit_index = 0;
    int byte_index = 0;
    int i;
    for (i=0; i<N/2*2; ) {   /* if length is an odd number, throw away the highest coeff */
        int coeff1 = poly->coeffs[i++] + 1;
        int coeff2 = poly->coeffs[i++] + 1;
        if (coeff1==0 && coeff2==0)
            return 1;
        int bit_tbl_index = coeff1*3 + coeff2;
        int j;
        int bits[] = {BIT1_TABLE[bit_tbl_index], BIT2_TABLE[bit_tbl_index], BIT3_TABLE[bit_tbl_index]};
        for (j=0; j<3; j++) {
            data[byte_index] |= bits[j] << bit_index;
            if (bit_index == 7) {
                bit_index = 0;
                byte_index++;
                data[byte_index] = 0;
            }
            else
                bit_index++;
        }
    }

    return 0;
}

/**
 * @brief Seed generation
 *
 * Generates a seed for the Blinding Polynomial Generation Function.
 *
 * @param msg the plain-text message
 * @param msg_len number of characters in msg
 * @param h the public key
 * @param b db bits of random data
 * @param params encryption parameters
 * @param seed output parameter; an array to write the seed value to
 * @return 0 for success, 1 for illegal encoding
 */
void ntru_get_seed(char *msg, int msg_len, NtruIntPoly *h, char *b, struct NtruEncParams *params, char *seed) {
    int oid_len = sizeof params->oid;
    int pklen = params->db / 8;

    char bh[ntru_enc_len(params->N, params->q)];
    ntru_to_arr(h, params->q, (char*)&bh);
    char htrunc[pklen];
    memcpy(&htrunc, &bh, pklen);

    /* seed = OID|m|b|htrunc */
    int blen = params->db/8;
    memcpy(seed, &params->oid, oid_len);
    seed += oid_len;
    memcpy(seed, msg, msg_len);
    seed += msg_len;
    memcpy(seed, b, blen);
    seed += blen;
    memcpy(seed, &htrunc, pklen);
}

void ntru_gen_tern_poly(NtruIGFState *s, int df, NtruTernPoly *p) {
    p->N = s->N;
    p->num_ones = df;
    p->num_neg_ones = df;

    int idx;
    int r[p->N];
    memset(r, 0, sizeof r);

    int t = 0;
    while (t < df) {
        ntru_IGF_next(s, &idx);
        if (!r[idx]) {
            p->neg_ones[t] = idx;
            r[idx] = 1;
            t++;
        }
    }
    t = 0;
    while (t < df) {
        ntru_IGF_next(s, &idx);
        if (!r[idx]) {
            p->ones[t] = idx;
            r[idx] = 1;
            t++;
        }
    }
}

void ntru_gen_blind_poly(char *seed, int seed_len, struct NtruEncParams *params, NtruProdPoly *r) {
    NtruIGFState s;
    ntru_IGF_init(seed, seed_len, params, &s);
    r->N = s.N;

    ntru_gen_tern_poly(&s, params->df1, &r->f1);
    ntru_gen_tern_poly(&s, params->df2, &r->f2);
    ntru_gen_tern_poly(&s, params->df3, &r->f3);
}

int ntru_encrypt(char *msg, int msg_len, NtruEncPubKey *pub, struct NtruEncParams *params, int (*rng)(unsigned[], int), char *enc) {
    int N = params->N;
    int q = params->q;
    int db = params->db;
    int max_len_bytes = ntru_max_msg_len(params);
    int buf_len_bits = (N*3/2+7)/8*8 + 1;
    int dm0 = params->dm0;

    if (max_len_bytes > 255)
        return NTRU_ERR_INVALID_MAX_LEN;
    if (msg_len > max_len_bytes)
        return NTRU_ERR_MSG_TOO_LONG;

    for (;;) {
        /* M = b|octL|msg|p0 */
        unsigned char b[db/8];
        if (!rng(&b, db/8/sizeof(int)))
            return NTRU_ERR_PRNG;

        int M_len = (buf_len_bits+7) / 8;
        unsigned char M[M_len];
        memcpy(&M, &b, db/8);
        unsigned char *M_head = (unsigned char*)&M + db/8;
        *M_head = msg_len;
        M_head++;
        memcpy(M_head, msg, msg_len);
        M_head += msg_len;
        memset(M_head, 0, max_len_bytes+1-msg_len);

        NtruIntPoly mtrin;
        ntru_from_sves((char*)&M, M_len, N, &mtrin);

        int blen = params->db / 8;
        int sdata_len = sizeof(params->oid) + msg_len + blen + blen;
        char sdata[sdata_len];
        ntru_get_seed(msg, msg_len, &pub->h, (char*)&b, params, (char*)&sdata);

        NtruProdPoly r;
        ntru_gen_blind_poly((char*)&sdata, sdata_len, params, &r);
        NtruIntPoly R;
        ntru_mult_prod(&pub->h, &r, &R);
        ntru_mod(&R, q);
        int oR4_len = (N*2+7) / 8;
        char oR4[oR4_len];
        ntru_to_arr4(&R, (char*)&oR4);
        NtruIntPoly mask;
        ntru_MGF((char*)&oR4, oR4_len, params, &mask);
        ntru_add_int(&mtrin, &mask);
        ntru_mod3(&mtrin);

        if (ntru_count(&mtrin, -1) < dm0)
            continue;
        if (ntru_count(&mtrin, 0) < dm0)
            continue;
        if (ntru_count(&mtrin, 1) < dm0)
            continue;

        ntru_add_int_mod(&R, &mtrin, q);
        ntru_to_arr(&R, q, enc);
        return 0;
    }
}

void ntru_decrypt_poly(NtruIntPoly *e, NtruEncPrivKey *priv, int q, NtruIntPoly *d) {
    ntru_mult_prod(e, &priv->t, d);
    ntru_mod(d, q);
    ntru_mult_fac(d, 3);
    ntru_add_int(d, e);
    ntru_mod_center(d, q);
    ntru_mod3(d);
}

int ntru_decrypt(char *enc, NtruEncKeyPair *kp, struct NtruEncParams *params, unsigned char *dec, int *dec_len) {
    int N = params->N;
    int q = params->q;
    int db = params->db;
    int max_len_bytes = ntru_max_msg_len(params);
    int dm0 = params->dm0;

    if (max_len_bytes > 255)
        return NTRU_ERR_INVALID_MAX_LEN;

    int blen = db / 8;

    NtruIntPoly e;
    ntru_from_arr(enc, N, q, &e);
    NtruIntPoly ci;
    ntru_decrypt_poly(&e, &kp->priv, q, &ci);

    if (ntru_count(&ci, -1) < dm0)
        return NTRU_ERR_DM0_VIOLATION;
    if (ntru_count(&ci, 0) < dm0)
        return NTRU_ERR_DM0_VIOLATION;
    if (ntru_count(&ci, 1) < dm0)
        return NTRU_ERR_DM0_VIOLATION;

    NtruIntPoly cR = e;
    ntru_sub_int(&cR, &ci);
    ntru_mod(&cR, q);

    int coR4_len = (N*2+7) / 8;
    char coR4[coR4_len];
    ntru_to_arr4(&cR, (char*)&coR4);

    NtruIntPoly mask;
    ntru_MGF((char*)&coR4, coR4_len, params, &mask);
    NtruIntPoly cmtrin = ci;
    ntru_sub_int(&cmtrin, &mask);
    ntru_mod3(&cmtrin);
    int cM_len_bits = (N*3+1) / 2;
    int cM_len_bytes = (cM_len_bits+7) / 8;
    unsigned char cM[cM_len_bytes];
    ntru_to_sves(&cmtrin, (char*)&cM);

    unsigned char cb[blen];
    unsigned char *cM_head = cM;
    memcpy(cb, cM_head, blen);
    cM_head += blen;
    int cl = *cM_head;   /* llen=1, so read one byte */
    cM_head++;
    if (cl > max_len_bytes)
        return NTRU_ERR_MSG_TOO_LONG;

    memcpy(dec, cM_head, cl);
    cM_head += cl;

    unsigned char *i;
    for (i=cM_head; i<cM+cM_len_bytes; i++)
        if (*i)
            return NTRU_ERR_NO_ZERO_PAD;

    int sdata_len = sizeof(params->oid) + cl + blen + db/8;
    char sdata[sdata_len];
    ntru_get_seed((char*)dec, cl, &kp->pub.h, (char*)&cb, params, (char*)&sdata);

    NtruProdPoly cr;
    ntru_gen_blind_poly((char*)&sdata, sdata_len, params, &cr);
    NtruIntPoly cR_prime;
    ntru_mult_prod(&kp->pub.h, &cr, &cR_prime);
    ntru_mod(&cR_prime, q);
    if (!ntru_equals_int(&cR_prime, &cR))
        return NTRU_ERR_INVALID_ENCODING;

    *dec_len = cl;
    return 0;
}

int ntru_max_msg_len(struct NtruEncParams *params) {
    int N = params->N;
    int llen = 1;   /* ceil(log2(max_len)) */
    int db = params->db;
    return N*3/2/8 - llen - db/8;;
}
