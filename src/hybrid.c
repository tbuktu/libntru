#include <stdio.h>
#include <string.h>
#include "ntru.h"
#include <openssl/evp.h>

/*****************************************************************************
 * Sample code that shows how to do hybrid encryption using NTRU and AES.    *
 *****************************************************************************/

int openssl_encr_decr(uint8_t *inbuf, int inlen, uint8_t *outbuf, int *outlen, uint8_t *key, uint8_t *iv, int do_encrypt) {
    EVP_CIPHER_CTX ctx;
    EVP_CIPHER_CTX_init(&ctx);
    EVP_CipherInit_ex(&ctx, EVP_aes_128_cbc(), NULL, NULL, NULL, do_encrypt);
    EVP_CipherInit_ex(&ctx, NULL, NULL, key, iv, do_encrypt);
    int retval = EVP_CipherUpdate(&ctx, outbuf, outlen, inbuf, inlen);
    int pad_bytes = 0;
    if (retval && !EVP_CipherFinal_ex(&ctx, outbuf+*outlen, &pad_bytes))
        retval = 0;
    *outlen += pad_bytes;
    EVP_CIPHER_CTX_cleanup(&ctx);
    return retval;
}

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
 *            ntru_enc_len(params)+msg_len+16 bytes.
 * @param enc_len output parameter; number of bytes written
 * @return NTRU_SUCCESS on success, or one of the NTRU_ERR_ codes on failure; 99 for OpenSSL error
 */
uint8_t ntru_encrypt_hybrid(uint8_t *msg, uint16_t msg_len, NtruEncPubKey *pub, NtruEncParams *params, NtruRandContext *rand_ctx, uint8_t *enc, int *enc_len) {
    uint8_t key_iv[32];   /* key + iv */
    rand_ctx->rand_gen->generate(key_iv, 32, rand_ctx);
    int retval = ntru_encrypt(key_iv, 32, pub, params, rand_ctx, enc);   /* put encrypted sym key + iv at the beginning */
    int outlen;
    if (!openssl_encr_decr(msg, msg_len, enc+ntru_enc_len(params), &outlen, key_iv, key_iv+16, 1))   /* followed by the encrypted msg */
        retval = 99;
    *enc_len = outlen;
    *enc_len += ntru_enc_len(params);    /* add length of encrypted sym key + iv */

    memset(key_iv, 0, 32);
    return retval;
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
 * @return NTRU_SUCCESS on success, or one of the NTRU_ERR_ codes on failure; 99 for OpenSSL error
 */
uint8_t ntru_decrypt_hybrid(uint8_t *enc, int enc_len, NtruEncKeyPair *kp, NtruEncParams *params, uint8_t *dec, int *dec_len) {
    uint8_t key_iv[32];
    uint16_t key_len;
    uint8_t retval = ntru_decrypt(enc, kp, params, key_iv, &key_len);
    if (retval != NTRU_SUCCESS)
        return retval;

    if (!openssl_encr_decr(enc+ntru_enc_len(params), enc_len-ntru_enc_len(params), dec, dec_len, key_iv, key_iv+16, 0))
        retval = 99;

    return retval;
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
    struct NtruEncParams params = EES449EP1;
    NtruEncKeyPair kp;
    NtruRandGen rng = NTRU_RNG_DEFAULT;
    NtruRandContext rand_ctx;
    ntru_rand_init(&rand_ctx, &rng);
    if (ntru_gen_key_pair(&params, &kp, &rand_ctx) != NTRU_SUCCESS)
        printf("keygen fail\n");

    /* encrypt */
    uint8_t enc[ntru_enc_len(&params)+strlen(plain_char)+16];
    int enc_len;
    if (ntru_encrypt_hybrid(plain, strlen(plain_char), &kp.pub, &params, &rand_ctx, enc, &enc_len) != NTRU_SUCCESS)
        printf("encrypt fail\n");

    /* decrypt */
    uint8_t dec[enc_len-ntru_enc_len(&params)];
    int dec_len;
    if (ntru_decrypt_hybrid((uint8_t*)&enc, enc_len, &kp, &params, (uint8_t*)&dec, &dec_len) != NTRU_SUCCESS)
        printf("decrypt fail\n");
    dec[dec_len] = 0;   /* string terminator */
    ntru_rand_release(&rand_ctx);

    printf("encryption+decryption ");
    printf(strcmp((char*)plain, (char*)dec)==0 ? "successful\n" : "failed\n");

    return 0;
}
