#ifndef HASH_H
#define HASH_H

void ntru_sha256(unsigned char *input, int input_len, unsigned char *digest);

void ntru_sha512(unsigned char *input, int input_len, unsigned char *digest);

#endif
