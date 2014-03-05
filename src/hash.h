#ifndef NTRU_HASH_H
#define NTRU_HASH_H

void ntru_sha256(char *input, int input_len, char *digest);

void ntru_sha512(char *input, int input_len, char *digest);

#endif   /* NTRU_HASH_H */
