#include "sph_sha2.h"
#include "hash.h"

void ntru_sha256(char *input, int input_len, char *digest) {
    sph_sha256_context context;

    sph_sha256_init(&context);
    sph_sha256(&context, input, input_len);
    sph_sha256_close(&context, digest);
}

void ntru_sha512(char *input, int input_len, char *digest) {
    sph_sha512_context context;

    sph_sha512_init(&context);
    sph_sha512(&context, input, input_len);
    sph_sha512_close(&context, digest);
}
