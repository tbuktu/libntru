#include "test_key.h"
#include "test_util.h"
#include "ntru.h"
#include "poly.h"

uint8_t test_export_import() {
#ifndef NTRU_AVOID_HAMMING_WT_PATENT
    NtruEncParams param_arr[] = {EES439EP1, EES1087EP2};
#else
    NtruEncParams param_arr[] = {EES1087EP2};
#endif   /* NTRU_AVOID_HAMMING_WT_PATENT */
    uint8_t valid = 1;

    uint8_t i;
    for (i=0; i<sizeof(param_arr)/sizeof(param_arr[0]); i++) {
        NtruEncParams params = param_arr[i];
        NtruEncKeyPair kp;
        NtruRandContext rand_ctx;
        NtruRandGen rng = NTRU_RNG_DEFAULT;
        ntru_rand_init(&rand_ctx, &rng);
        ntru_gen_key_pair(&params, &kp, &rand_ctx);
        valid &= ntru_rand_release(&rand_ctx) == NTRU_SUCCESS;

        /* test public key */
        uint8_t pub_arr[ntru_pub_len(&params)];
        ntru_export_pub(&kp.pub, pub_arr);
        NtruEncPubKey pub;
        ntru_import_pub(pub_arr, &pub);
        valid &= ntru_equals_int(&kp.pub.h, &pub.h);

        /* test private key */
        uint8_t priv_arr[ntru_priv_len(&params)];
        uint16_t priv_len = ntru_export_priv(&kp.priv, priv_arr);
        valid &= priv_len == ntru_priv_len(&params);
        NtruEncPrivKey priv;
        ntru_import_priv(priv_arr, &priv);
        NtruIntPoly t_int1, t_int2;
        ntru_priv_to_int(&priv.t, &t_int1, params.q);
        ntru_priv_to_int(&kp.priv.t, &t_int2, params.q);
        valid &= ntru_equals_int(&t_int1, &t_int2);
    }

    return valid;
}

/* tests ntru_params_from_priv_key() and ntru_params_from_key_pair() */
uint8_t test_params_from_key() {
    NtruEncParams param_arr[] = ALL_PARAM_SETS;
    uint8_t valid = 1;

    uint8_t i;
    for (i=0; i<sizeof(param_arr)/sizeof(param_arr[0]); i++) {
        NtruEncParams params = param_arr[i];
        NtruRandContext rand_ctx;
        NtruRandGen rng = NTRU_RNG_DEFAULT;
        ntru_rand_init(&rand_ctx, &rng);
        NtruEncKeyPair kp;
        valid &= ntru_gen_key_pair(&params, &kp, &rand_ctx) == NTRU_SUCCESS;
        valid &= ntru_rand_release(&rand_ctx) == NTRU_SUCCESS;

        NtruEncParams params2;
        valid &= ntru_params_from_priv_key(&kp.priv, &params2) == NTRU_SUCCESS;
        valid &= equals_params(&params, &params2);
        valid &= ntru_params_from_key_pair(&kp, &params2) == NTRU_SUCCESS;
        valid &= equals_params(&params, &params2);
    }

    for (i=0; i<sizeof(param_arr)/sizeof(param_arr[0]); i++) {
        NtruEncParams params1 = param_arr[i];
        uint8_t j;
        for (j=0; j<sizeof(param_arr)/sizeof(param_arr[0]); j++) {
            NtruEncParams params2 = param_arr[j];
            valid &= equals_params(&params1, &params2) == (i==j);
        }
    }

    return valid;
}

uint8_t test_key() {
    uint8_t valid = test_export_import();
    valid &= test_params_from_key();
    print_result("test_key", valid);
    return valid;
}
