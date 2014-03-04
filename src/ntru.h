#ifndef NTRU_H
#define NTRU_H

#include "types.h"
#include "key.h"
#include "poly.h"
#include "encparams.h"
#include "rand.h"

/**
 * @brief Key generation
 *
 * Generates a (non-deterministically) random NtruEncrypt key pair.
 *
 * @param params the NtruEncrypt parameters to use
 * @param kp pointer to write the key pair to (output parameter)
 * @param rng a pointer to a function that takes an array and an array size, and fills the array
 *            with random data. See the ntru_rand_* functions.
 * @return NTRU_SUCCESS for success, or a NTRU_ERR_ code for failure
 */
int ntru_gen_key_pair(NtruEncParams *params, NtruEncKeyPair *kp, int (*rng)(unsigned[], int, NtruRandContext*));

/**
 * @brief Deterministic key generation
 *
 * Generates an NtruEncrypt key pair which is determined by a random seed.
 * For a given set of NTRU parameters and a given random seed, the key pair
 * will always be the same.
 *
 * @param params the NtruEncrypt parameters to use
 * @param kp pointer to write the key pair to (output parameter)
 * @param rng a pointer to a function that takes an array and an array size, and fills the array
 *            with pseudo-random data determined by the NtruRandContext. See the ntru_rand_* functions.
 * @param seed seed value
 * @param seed_len length of the seed parameter
 * @return NTRU_SUCCESS for success, or a NTRU_ERR_ code for failure
 */
int ntru_gen_key_pair_det(NtruEncParams *params, NtruEncKeyPair *kp, int (*rng)(unsigned[], int, NtruRandContext*), char *seed, int seed_len);

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
 *            with random data. See the ntru_rand_* functions.
 * @param enc output parameter; a pointer to store the encrypted message. Must accommodate
              ntru_enc_len(params) bytes.
 * @return NTRU_SUCCESS on success, or one of the NTRU_ERR_ codes on failure
 */
int ntru_encrypt(char *msg, int msg_len, NtruEncPubKey *pub, NtruEncParams *params, int (*rng)(unsigned[], int, NtruRandContext*), char *enc);

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
 * @return NTRU_SUCCESS on success, or one of the NTRU_ERR_ codes on failure
 */
int ntru_decrypt(char *enc, NtruEncKeyPair *kp, NtruEncParams *params, unsigned char *dec, int *dec_len);

int ntru_max_msg_len(NtruEncParams *params);

#endif   /* NTRU_H */
