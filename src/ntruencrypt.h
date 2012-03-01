#ifndef NTRUENCRYPT_H
#define NTRUENCRYPT_H

#include "poly.h"
#include "encparams.h"

/**
 * NtruEncrypt private key
 */
typedef struct NtruEncPrivKey {
    struct NtruEncParams params;
    NtruProdPoly t;
} NtruEncPrivKey;

/**
 * NtruEncrypt public key
 */
typedef struct NtruEncPubKey {
    struct NtruEncParams params;
    NtruIntPoly h;
} NtruEncPubKey;

/**
 * NtruEncrypt key pair
 */
typedef struct NtruEncKeyPair {
    NtruEncPrivKey priv;
    NtruEncPubKey pub;
} NtruEncKeyPair;

/**
 * @brief Key generation
 *
 * Generates an NtruEncrypt key pair.
 *
 * @param params the NtruEncrypt parameters to use
 * @param kp pointer to write the key pair to (output parameter)
 * @param rng a pointer to a function that takes an array and an array size, and fills the array
 *            with random data. See dev_random() and dev_urandom().
 * @return 1 for success, 0 for failure
 */
int ntru_gen_key_pair(struct NtruEncParams params, NtruEncKeyPair *kp, int (*rng)(unsigned[], int));

#endif   /* NTRUENCRYPT_H */
