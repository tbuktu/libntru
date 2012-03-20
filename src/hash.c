#include <openssl/sha.h>
#include "hash.h"

void ntru_sha256(char *input, int input_len, char *digest) {
    SHA256_CTX context;
    SHA256_Init(&context);
    SHA256_Update(&context, input, input_len);
    SHA256_Final((unsigned char*)digest, &context);
}

void ntru_sha512(char *input, int input_len, char *digest) {
    SHA512_CTX context;
    SHA512_Init(&context);
    SHA512_Update(&context, input, input_len);
    SHA512_Final((unsigned char*)digest, &context);
}
