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

/**
 * @brief Encryption
 *
 * Encrypts a message.
 * See P1363.1 section 9.2.2.
 *
 * @param msg The message to encrypt
 * @param msg_len length of msg
 * @param pub the public key to encrypt the message with
 * @param params the NtruEncrypt parameters to use
 * @param rng a pointer to a function that takes an array and an array size, and fills the array
 *            with random data. See dev_random() and dev_urandom().
 * @param enc output parameter; a pointer to store the encrypted message. Must accommodate
              ntru_enc_len(params) bytes.
 * @return 0 on success, or one of the NTRU_ERR_ codes on failure
 */
int ntru_encrypt(char *msg, int msg_len, NtruEncPubKey *pub, struct NtruEncParams *params, int (*rng)(unsigned[], int), char *enc);

int ntru_enc_len(struct NtruEncParams *params);

/**
 * @brief Decryption
 *
 * Decrypts a message.
 * See P1363.1 section 9.2.3.
 *
 * @param enc The message to decrypt
 * @param kp a key pair that contains the public key the message was encrypted
             with, and the corresponding private key
 * @param params the NtruEncrypt parameters the message was encrypted with
 * @param dec output parameter; a pointer to store the decrypted message. Must accommodate
              ntru_max_msg_len(params) bytes.
 * @param dec_len output parameter; pointer to store the length of dec
 * @return 0 on success, or one of the NTRU_ERR_ codes on failure
 */
int ntru_decrypt(char *enc, NtruEncKeyPair *kp, struct NtruEncParams *params, unsigned char *dec, int *dec_len);

int ntru_max_msg_len(struct NtruEncParams *params);

#endif   /* NTRUENCRYPT_H */
