#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "ntru.h"
#include "rand.h"
#include "poly.h"
#include "idxgen.h"
#include "mgf.h"

/** Whether to ensure g is invertible when generating a key */
#define NTRU_CHECK_INVERTIBILITY_G 0

const int8_t NTRU_COEFF1_TABLE[] = {0, 0, 0, 1, 1, 1, -1, -1};
const int8_t NTRU_COEFF2_TABLE[] = {0, 1, -1, 0, 1, -1, 0, 1};

/* Generates a random g. If NTRU_CHECK_INVERTIBILITY_G, g will be invertible mod q */
uint8_t ntru_gen_g(const NtruEncParams *params, NtruPrivPoly *g, NtruRandContext *rand_ctx) {
    uint16_t N = params->N;
#ifndef NTRU_AVOID_HAMMING_WT_PATENT
    uint16_t df1 = params->df1;
    uint16_t df2 = params->df2;
    uint16_t df3 = params->df3;
#endif   /* NTRU_AVOID_HAMMING_WT_PATENT */
    uint16_t dg = N / 3;
    for (;;) {
#ifndef NTRU_AVOID_HAMMING_WT_PATENT
        if (params->prod_flag && !ntru_rand_prod(N, df1, df2, df3, df3, &g->poly.prod, rand_ctx))
            return NTRU_ERR_PRNG;
        if (!params->prod_flag && !ntru_rand_tern(N, dg, dg, &g->poly.tern, rand_ctx))
            return NTRU_ERR_PRNG;
        g->prod_flag = params->prod_flag;
#else
        if (!ntru_rand_tern(N, dg, dg, &g->poly.tern, rand_ctx))
            return NTRU_ERR_PRNG;
        g->prod_flag = 0;
#endif   /* NTRU_AVOID_HAMMING_WT_PATENT */

        if (!NTRU_CHECK_INVERTIBILITY_G)
            break;
        NtruIntPoly gq;
        if (ntru_invert(g, params->q-1, &gq))
            break;
    }
    return NTRU_SUCCESS;
}

uint8_t ntru_gen_key_pair_single(const NtruEncParams *params, NtruEncPrivKey *priv, NtruEncPubKey *pub, NtruIntPoly *fq, NtruRandContext *rand_ctx) {
    uint16_t N = params->N;
    uint16_t q = params->q;
    uint16_t df1 = params->df1;
#ifndef NTRU_AVOID_HAMMING_WT_PATENT
    uint16_t df2 = params->df2;
    uint16_t df3 = params->df3;
#endif   /* NTRU_AVOID_HAMMING_WT_PATENT */

    if (q & (q-1))   /* check that modulus is a power of 2 */
        return NTRU_ERR_INVALID_PARAM;

    /* choose a random f that is invertible mod q */
#ifndef NTRU_AVOID_HAMMING_WT_PATENT
    if (params->prod_flag) {
        NtruPrivPoly *t = &priv->t;
        t->prod_flag = 1;
        t->poly.prod.N = N;
        priv->q = q;
        for (;;) {
            /* choose random t, find the inverse of 3t+1 */
            if (!ntru_rand_prod(N, df1, df2, df3, df3, &t->poly.prod, rand_ctx))
                return NTRU_ERR_PRNG;
            if (ntru_invert(t, q-1, fq))
                break;
        }
    }
    else
#endif   /* NTRU_AVOID_HAMMING_WT_PATENT */
    {
        NtruPrivPoly *t = &priv->t;
        t->prod_flag = 0;
        priv->q = q;
        for (;;) {
            /* choose random t, find the inverse of 3t+1 */
            if (!ntru_rand_tern(N, df1, df1, &t->poly.tern, rand_ctx))
                return NTRU_ERR_PRNG;
            if (ntru_invert(t, q-1, fq))
                break;
        }
    }

    /* choose a random g */
    NtruPrivPoly g;
    uint8_t result = ntru_gen_g(params, &g, rand_ctx);
    if (result != NTRU_SUCCESS)
        return result;

    NtruIntPoly *h = &pub->h;
    if (!ntru_mult_priv(&g, fq, h, q-1))
        return NTRU_ERR_PRNG;
    ntru_mult_fac(h, 3);
    ntru_mod_mask(h, q-1);

    ntru_clear_priv(&g);

    pub->q = q;

    return NTRU_SUCCESS;
}

uint8_t ntru_gen_key_pair(const NtruEncParams *params, NtruEncKeyPair *kp, NtruRandContext *rand_ctx) {
    NtruIntPoly fq;
    uint8_t result = ntru_gen_key_pair_single(params, &kp->priv, &kp->pub, &fq, rand_ctx);
    ntru_clear_int(&fq);
    return result;
}

uint8_t ntru_gen_key_pair_multi(const NtruEncParams *params, NtruEncPrivKey *priv, NtruEncPubKey *pub, NtruRandContext *rand_ctx, uint32_t num_pub) {
    uint16_t q = params->q;
    NtruIntPoly fq;
    uint8_t result = ntru_gen_key_pair_single(params, priv, pub, &fq, rand_ctx);
    if (result != NTRU_SUCCESS)
        return result;
    uint32_t i;
    for (i=1; i<num_pub; i++) {
        NtruIntPoly *h = &pub[i].h;
        NtruPrivPoly g;
        result = ntru_gen_g(params, &g, rand_ctx);
        if (result != NTRU_SUCCESS)
            return result;
        if (!ntru_mult_priv(&g, &fq, h, q-1))
            return NTRU_ERR_PRNG;
        ntru_mult_fac(h, 3);
        ntru_mod_mask(h, q-1);
        pub[i].q = q;
    }
    ntru_clear_int(&fq);
    return result;
}

uint8_t ntru_gen_pub(const NtruEncParams *params, NtruEncPrivKey *priv, NtruEncPubKey *pub, NtruRandContext *rand_ctx) {
    uint16_t q = params->q;
    NtruIntPoly fq;
    if (!ntru_invert(&priv->t, q-1, &fq))
        return NTRU_ERR_INVALID_KEY;
    NtruIntPoly *h = &pub->h;
    NtruPrivPoly g;
    uint8_t result = ntru_gen_g(params, &g, rand_ctx);
    if (result != NTRU_SUCCESS)
        return result;
    if (!ntru_mult_priv(&g, &fq, h, q-1))
        return NTRU_ERR_PRNG;
    ntru_clear_int(&fq);
    ntru_mult_fac(h, 3);
    ntru_mod_mask(h, q-1);
    pub->q = q;
    return NTRU_SUCCESS;
}

/**
 * @brief byte array to ternary polynomial
 *
 * Decodes a uint8_t array encoded with ntru_to_sves() back to a polynomial with N
 * coefficients between -1 and 1.
 * Ignores any excess bytes.
 * See P1363.1 section 9.2.2.
 *
 * @param M an encoded ternary polynomial
 * @param M_len number of elements in M
 * @param N number of coefficients to generate
 * @param poly output parameter; pointer to write the polynomial to
 */
void ntru_from_sves(uint8_t *M, uint16_t M_len, uint16_t N, NtruIntPoly *poly) {
    poly->N = N;

    uint16_t coeff_idx = 0;
    uint16_t i = 0;
    while (i<(M_len+2)/3*3 && coeff_idx<N-1) {
        /* process 24 bits at a time in the outer loop */
        int32_t chunk = (uint8_t)M[i+2];
        chunk <<= 8;
        chunk += (uint8_t)M[i+1];
        chunk <<= 8;
        chunk += (uint8_t)M[i];
        i += 3;

        uint8_t j;
        for (j=0; j<8 && coeff_idx<N-1; j++) {
            /* process 3 bits at a time in the inner loop */
            uint8_t coeff_tbl_idx = chunk & 7;   /* low 3 bits */
            poly->coeffs[coeff_idx++] = NTRU_COEFF1_TABLE[coeff_tbl_idx];
            poly->coeffs[coeff_idx++] = NTRU_COEFF2_TABLE[coeff_tbl_idx];
            chunk >>= 3;
        }
    }

    while (coeff_idx < N)
        poly->coeffs[coeff_idx++] = 0;
}

/**
 * @brief Ternary polynomial to byte array
 *
 * Encodes a polynomial whose elements are between 0 and 2, to a uint8_t array.
 * The (2*i)-th coefficient and the (2*i+1)-th coefficient must not both equal
 * 2 for any integer i, so this method is only safe to use with arrays
 * produced by ntru_from_sves().
 * See P1363.1 section 9.2.3.
 *
 * @param poly a ternary polynomial
 * @param data output parameter; must accommodate ceil(num_bits/8)+3 bytes
 * @return 1 for success, 0 for invalid encoding
 */
uint8_t ntru_to_sves(NtruIntPoly *poly, uint8_t *data) {
    uint16_t N = poly->N;

    uint16_t num_bits = (N*3+1) / 2;
    memset(data, 0, (num_bits+7)/8);

    uint16_t i;
    uint16_t start = 0;
    uint16_t end = N/2*2;   /* if there is an odd number of coeffs, throw away the highest one */

    memset(&poly->coeffs[N], 0, 2*15);   /* we process coefficients in blocks of 16, so clear the last block */
    uint16_t d_idx = 0;
    uint8_t valid = 1;
    for (i=start; i<end; ) {
        int16_t coeff1 = poly->coeffs[i++];
        int16_t coeff2 = poly->coeffs[i++];
        if (coeff1==2 && coeff2==2)
            valid = 0;
        int16_t c = coeff1*3 + coeff2;
        data[d_idx] = c;

        coeff1 = poly->coeffs[i++];
        coeff2 = poly->coeffs[i++];
        if (coeff1==2 && coeff2==2)
            valid = 0;
        c = coeff1*3 + coeff2;
        data[d_idx] |= c << 3;

        coeff1 = poly->coeffs[i++];
        coeff2 = poly->coeffs[i++];
        if (coeff1==2 && coeff2==2)
            valid = 0;
        c = coeff1*3 + coeff2;
        data[d_idx] |= c << 6;
        d_idx++;
        data[d_idx] = c >> 2;

        coeff1 = poly->coeffs[i++];
        coeff2 = poly->coeffs[i++];
        if (coeff1==2 && coeff2==2)
            valid = 0;
        c = coeff1*3 + coeff2;
        data[d_idx] |= c << 1;

        coeff1 = poly->coeffs[i++];
        coeff2 = poly->coeffs[i++];
        if (coeff1==2 && coeff2==2)
            valid = 0;
        c = coeff1*3 + coeff2;
        data[d_idx] |= c << 4;

        coeff1 = poly->coeffs[i++];
        coeff2 = poly->coeffs[i++];
        if (coeff1==2 && coeff2==2)
            valid = 0;
        c = coeff1*3 + coeff2;
        data[d_idx] |= c << 7;
        d_idx++;
        data[d_idx] = c >> 1;

        coeff1 = poly->coeffs[i++];
        coeff2 = poly->coeffs[i++];
        if (coeff1==2 && coeff2==2)
            valid = 0;
        c = coeff1*3 + coeff2;
        data[d_idx] |= c << 2;

        coeff1 = poly->coeffs[i++];
        coeff2 = poly->coeffs[i++];
        if (coeff1==2 && coeff2==2)
            valid = 0;
        c = coeff1*3 + coeff2;
        data[d_idx] |= c << 5;
        d_idx++;
    }

    return valid;
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
 */
void ntru_get_seed(uint8_t *msg, uint16_t msg_len, NtruIntPoly *h, uint8_t *b, const NtruEncParams *params, uint8_t *seed) {
    uint16_t oid_len = sizeof params->oid;
    uint16_t pklen = params->pklen;

    uint8_t bh[ntru_enc_len(params)];
    ntru_to_arr(h, params->q, (uint8_t*)&bh);
    uint8_t htrunc[pklen/8];
    memcpy(&htrunc, &bh, pklen/8);

    /* seed = OID|m|b|htrunc */
    uint16_t blen = params->db/8;
    memcpy(seed, &params->oid, oid_len);
    seed += oid_len;
    memcpy(seed, msg, msg_len);
    seed += msg_len;
    memcpy(seed, b, blen);
    seed += blen;
    memcpy(seed, &htrunc, pklen/8);
}

void ntru_gen_tern_poly(NtruIGFState *s, uint16_t df, NtruTernPoly *p) {
    p->N = s->N;
    p->num_ones = df;
    p->num_neg_ones = df;

    uint16_t idx;
    uint16_t r[p->N];
    memset(r, 0, sizeof r);

    uint16_t t = 0;
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

void ntru_gen_blind_poly(uint8_t *seed, uint16_t seed_len, const NtruEncParams *params, NtruPrivPoly *r) {
    NtruIGFState s;
    ntru_IGF_init(seed, seed_len, params, &s);

#ifndef NTRU_AVOID_HAMMING_WT_PATENT
    if (params->prod_flag) {
        r->poly.prod.N = s.N;
        ntru_gen_tern_poly(&s, params->df1, &r->poly.prod.f1);
        ntru_gen_tern_poly(&s, params->df2, &r->poly.prod.f2);
        ntru_gen_tern_poly(&s, params->df3, &r->poly.prod.f3);
    }
    else
#endif   /* NTRU_AVOID_HAMMING_WT_PATENT */
    {
        r->poly.tern.N = s.N;
        ntru_gen_tern_poly(&s, params->df1, &r->poly.tern);
    }
    r->prod_flag = params->prod_flag;
}

/* All elements of p->coeffs must be in the [0..2] range */
uint8_t ntru_check_rep_weight(NtruIntPoly *p, uint16_t dm0) {
    uint16_t i;
    uint16_t weights[3];
    weights[0] = weights[1] = weights[2] = 0;

    for (i=0; i<p->N; i++)
        weights[p->coeffs[i]]++;

    return (weights[0]>=dm0 && weights[1]>=dm0 && weights[2]>=dm0);
}

uint8_t ntru_encrypt(uint8_t *msg, uint16_t msg_len, NtruEncPubKey *pub, const NtruEncParams *params, NtruRandContext *rand_ctx, uint8_t *enc) {
    uint16_t N = params->N;
    uint16_t q = params->q;
    uint16_t db = params->db;
    uint16_t max_len_bytes = ntru_max_msg_len(params);
    uint16_t dm0 = params->dm0;

    if (q & (q-1))   /* check that modulus is a power of 2 */
        return NTRU_ERR_INVALID_PARAM;
    if (max_len_bytes > 255)
        return NTRU_ERR_INVALID_MAX_LEN;
    if (msg_len > max_len_bytes)
        return NTRU_ERR_MSG_TOO_LONG;

    for (;;) {
        /* M = b|octL|msg|p0 */
        uint8_t b[db/8];
        if (ntru_rand_generate(b, db/8, rand_ctx) != NTRU_SUCCESS)
            return NTRU_ERR_PRNG;

        uint16_t M_len = db/8 + 1 + max_len_bytes + 1;
        uint8_t M[M_len];
        memcpy(&M, &b, db/8);
        uint8_t *M_head = (uint8_t*)&M + db/8;
        *M_head = msg_len;
        M_head++;
        memcpy(M_head, msg, msg_len);
        M_head += msg_len;
        memset(M_head, 0, max_len_bytes+1-msg_len);

        NtruIntPoly mtrin;
        ntru_from_sves((uint8_t*)&M, M_len, N, &mtrin);

        uint16_t blen = params->db / 8;
        uint16_t sdata_len = sizeof(params->oid) + msg_len + blen + blen;
        uint8_t sdata[sdata_len];
        ntru_get_seed(msg, msg_len, &pub->h, (uint8_t*)&b, params, (uint8_t*)&sdata);

        NtruIntPoly R;
        NtruPrivPoly r;
        ntru_gen_blind_poly((uint8_t*)&sdata, sdata_len, params, &r);
        ntru_mult_priv(&r, &pub->h, &R, q-1);
        uint16_t oR4_len = (N*2+7) / 8;
        uint8_t oR4[oR4_len];
        ntru_to_arr4(&R, (uint8_t*)&oR4);
        NtruIntPoly mask;
        ntru_MGF((uint8_t*)&oR4, oR4_len, params, &mask);
        ntru_add_int(&mtrin, &mask);

        ntru_mod3(&mtrin);

        if (!ntru_check_rep_weight(&mtrin, dm0))
            continue;

        ntru_add_int(&R, &mtrin);
        ntru_to_arr(&R, q, enc);
        return NTRU_SUCCESS;
    }
}

void ntru_decrypt_poly(NtruIntPoly *e, NtruEncPrivKey *priv, uint16_t q, NtruIntPoly *d) {
    ntru_mult_priv(&priv->t, e, d, q-1);
    ntru_mult_fac(d, 3);
    ntru_add_int(d, e);
    ntru_mod_center(d, q);
    ntru_mod3(d);
}

uint8_t ntru_decrypt(uint8_t *enc, NtruEncKeyPair *kp, const NtruEncParams *params, uint8_t *dec, uint16_t *dec_len) {
    uint16_t N = params->N;
    uint16_t q = params->q;
    uint16_t db = params->db;
    uint16_t max_len_bytes = ntru_max_msg_len(params);
    uint16_t dm0 = params->dm0;

    if (q & (q-1))   /* check that modulus is a power of 2 */
        return NTRU_ERR_INVALID_PARAM;
    if (max_len_bytes > 255)
        return NTRU_ERR_INVALID_MAX_LEN;

    uint16_t blen = db / 8;
    uint8_t retcode = NTRU_SUCCESS;

    NtruIntPoly e;
    ntru_from_arr(enc, N, q, &e);
    NtruIntPoly ci;
    ntru_decrypt_poly(&e, &kp->priv, q, &ci);

    if (!ntru_check_rep_weight(&ci, dm0) && retcode==NTRU_SUCCESS)
        retcode = NTRU_ERR_DM0_VIOLATION;

    NtruIntPoly cR = e;
    ntru_sub_int(&cR, &ci);
    ntru_mod_mask(&cR, q-1);

    uint16_t coR4_len = (N*2+7) / 8;
    uint8_t coR4[coR4_len];
    ntru_to_arr4(&cR, (uint8_t*)&coR4);

    NtruIntPoly mask;
    ntru_MGF((uint8_t*)&coR4, coR4_len, params, &mask);
    NtruIntPoly cmtrin = ci;
    ntru_sub_int(&cmtrin, &mask);
    ntru_mod3(&cmtrin);
    uint16_t cM_len_bits = (N*3+1) / 2;
    uint16_t cM_len_bytes = (cM_len_bits+7) / 8;
    uint8_t cM[cM_len_bytes+3];   /* 3 extra bytes for ntru_to_sves() */
    if (!ntru_to_sves(&cmtrin, (uint8_t*)&cM) && retcode==NTRU_SUCCESS)
        retcode = NTRU_ERR_INVALID_ENCODING;

    uint8_t cb[blen];
    uint8_t *cM_head = cM;
    memcpy(cb, cM_head, blen);
    cM_head += blen;
    uint8_t cl = *cM_head;   /* llen=1, so read one byte */
    cM_head++;
    if (cl > max_len_bytes) {
        if (retcode == NTRU_SUCCESS)
            retcode = NTRU_ERR_MSG_TOO_LONG;
        cl = max_len_bytes;   /* prevent buffer overrun in memcpy below */
    }

    memcpy(dec, cM_head, cl);
    cM_head += cl;

    uint8_t *i;
    for (i=cM_head; i<cM+cM_len_bytes; i++)
        if (*i && retcode==NTRU_SUCCESS)
            retcode = NTRU_ERR_NO_ZERO_PAD;

    uint16_t sdata_len = sizeof(params->oid) + cl + blen + db/8;
    uint8_t sdata[sdata_len];
    ntru_get_seed(dec, cl, &kp->pub.h, (uint8_t*)&cb, params, (uint8_t*)&sdata);

    NtruPrivPoly cr;
    ntru_gen_blind_poly((uint8_t*)&sdata, sdata_len, params, &cr);
    NtruIntPoly cR_prime;
    ntru_mult_priv(&cr, &kp->pub.h, &cR_prime, q-1);
    if (!ntru_equals_int(&cR_prime, &cR) && retcode==NTRU_SUCCESS)
        retcode = NTRU_ERR_INVALID_ENCODING;

    *dec_len = cl;
    return retcode;
}

uint8_t ntru_max_msg_len(const NtruEncParams *params) {
    uint16_t N = params->N;
    uint8_t llen = 1;   /* ceil(log2(max_len)) */
    uint16_t db = params->db;
    uint16_t max_msg_len;
    max_msg_len = N/2*3/8 - llen - db/8;
    return max_msg_len;
}
