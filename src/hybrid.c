#include <stdio.h>
#include <string.h>
#include "ntru.h"
#include <sodium.h>

/********************************************************************************
 * Sample code that shows how to do hybrid encryption using NTRU and libsodium. *
 ********************************************************************************/

/**
 * @brief Hybrid Encryption
 *
 * Encrypts a message of arbitrary length.
 *
 * @param msg The message to encrypt
 * @param msg_len length of msg
 * @param pub the public key to encrypt the message with
 * @param params the NtruEncrypt parameters to use
 * @param rand_ctx an initialized random number generator. See ntru_rand_init() in rand.h.
 * @param enc output parameter; a pointer to store the encrypted message. Must accommodate
 *            ntru_enc_len(params)+msg_len+crypto_secretbox_MACBYTES bytes.
 * @param enc_len output parameter; number of bytes written
 * @return NTRU_SUCCESS on success, or one of the NTRU_ERR_ codes on failure; 99 for libsodium error
 */
uint8_t ntru_encrypt_hybrid(uint8_t *msg, uint16_t msg_len, NtruEncPubKey *pub, const NtruEncParams *params, NtruRandContext *rand_ctx, uint8_t *enc, int *enc_len) {
    if (sodium_init() == -1)
        return 99;
    uint8_t key_nonce[crypto_secretbox_KEYBYTES + crypto_secretbox_NONCEBYTES];   /* key + nonce */
    uint8_t *key = key_nonce;
    uint8_t *nonce = key_nonce + crypto_secretbox_KEYBYTES;
    randombytes_buf(key, crypto_secretbox_KEYBYTES);
    randombytes_buf(nonce, crypto_secretbox_NONCEBYTES);
    int retval = ntru_encrypt(key_nonce, sizeof key_nonce, pub, params, rand_ctx, enc);   /* put encrypted sym key + nonce at the beginning */
    if (retval != NTRU_SUCCESS)
        return retval;

    crypto_secretbox_easy(enc+ntru_enc_len(params), msg, msg_len, nonce, key);   /* ...followed by the encrypted msg */
    *enc_len = crypto_secretbox_MACBYTES + msg_len;
    *enc_len += ntru_enc_len(params);    /* add length of encrypted sym key + nonce */

    memset(key_nonce, 0, sizeof key_nonce);
    return NTRU_SUCCESS;
}

/**
 * @brief Hybrid Decryption
 *
 * Decrypts a message encrypted with ntru_encrypt_hybrid().
 *
 * @param enc The message to decrypt
 * @param enc_len length of enc
 * @param kp a key pair that contains the public key the message was encrypted
 *           with, and the corresponding private key
 * @param params the NtruEncrypt parameters the message was encrypted with
 * @param dec output parameter; a pointer to store the decrypted message. Must accommodate
 *            enc_len-ntru_enc_len(params) bytes.
 * @param dec_len output parameter; pointer to store the length of dec
 * @return NTRU_SUCCESS on success, or one of the NTRU_ERR_ codes on failure; 99 for authentication failure
 */
uint8_t ntru_decrypt_hybrid(uint8_t *enc, int enc_len, NtruEncKeyPair *kp, const NtruEncParams *params, uint8_t *dec, int *dec_len) {
    uint8_t key_nonce[crypto_secretbox_KEYBYTES + crypto_secretbox_NONCEBYTES];   /* key + nonce */
    uint8_t *key = key_nonce;
    uint8_t *nonce = key_nonce + crypto_secretbox_KEYBYTES;
    uint16_t key_len;
    uint8_t retval = ntru_decrypt(enc, kp, params, key_nonce, &key_len);
    if (retval != NTRU_SUCCESS)
        return retval;

    enc_len -= ntru_enc_len(params);
    if (crypto_secretbox_open_easy(dec, enc+ntru_enc_len(params), enc_len, nonce, key) != 0)
        return 99;

    *dec_len = enc_len - crypto_secretbox_MACBYTES;
    return NTRU_SUCCESS;
}

int main(int arc, char **argv) {
    char plain_char[123];
    strcpy(plain_char, "This text is too long to fit in a NTRU message, so we'll use " \
                       "symmetric encryption and then NTRU-encrypt the symmetric key.");
    uint8_t plain[strlen(plain_char)];
    unsigned i;
    for (i=0; i<strlen(plain_char); i++)
        plain[i] = plain_char[i];

    /* generate an NTRU key */
    NtruEncKeyPair kp;
    NtruRandGen rng = NTRU_RNG_DEFAULT;
    NtruRandContext rand_ctx;
    if (ntru_rand_init(&rand_ctx, &rng) != NTRU_SUCCESS)
        printf("rng fail\n");
    if (ntru_gen_key_pair(&NTRU_DEFAULT_PARAMS_128_BITS, &kp, &rand_ctx) != NTRU_SUCCESS)
        printf("keygen fail\n");

    /* encrypt */
    uint8_t enc[ntru_enc_len(&NTRU_DEFAULT_PARAMS_128_BITS)+strlen(plain_char)+16];
    int enc_len;
    if (ntru_encrypt_hybrid(plain, strlen(plain_char), &kp.pub, &NTRU_DEFAULT_PARAMS_128_BITS, &rand_ctx, enc, &enc_len) != NTRU_SUCCESS)
        printf("encrypt fail\n");

    /* decrypt */
    uint8_t dec[enc_len-ntru_enc_len(&NTRU_DEFAULT_PARAMS_128_BITS)];
    int dec_len;
    if (ntru_decrypt_hybrid((uint8_t*)&enc, enc_len, &kp, &NTRU_DEFAULT_PARAMS_128_BITS, (uint8_t*)&dec, &dec_len) != NTRU_SUCCESS)
        printf("decrypt fail\n");
    dec[dec_len] = 0;   /* string terminator */
    ntru_rand_release(&rand_ctx);
    printf("Decrypted text: \"%s\"\n", dec);

    printf("encryption+decryption ");
    printf(strcmp((char*)plain, (char*)dec)==0 ? "successful\n" : "failed\n");

    return 0;
}
