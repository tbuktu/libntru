#include <stdlib.h>
#include "ntruencrypt.h"

int ntru_gen_key_pair(NtruEncParams params, NtruEncKeyPair *kp, int (*rng)(unsigned[], int)) {
    int N = params.N;
    int q = params.q;
    int df1 = params.df1;
    int df2 = params.df2;
    int df3 = params.df3;

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

    NtruEncPrivKey priv = {params, t};
    kp->priv = priv;
    NtruEncPubKey pub = {params, h};
    kp->pub = pub;

    return 1;
}
