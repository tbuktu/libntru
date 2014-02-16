#include <stdio.h>
#include <string.h>
#include <time.h>
#include "ntru.h"

#define NUM_ITER 10000

int main(int argc, char **argv) {
    printf("Please wait...\n");

    NtruEncKeyPair kp;

    struct NtruEncParams params = APR2011_439_FAST;
    int success = ntru_gen_key_pair(&params, &kp, dev_urandom) == 0;
    int enc_len = ntru_enc_len(params.N, params.q);
    char plain[33];
    strcpy(plain, "test message secret test message");
    char encrypted[enc_len];
    char decrypted[strlen(plain)];
    int i;
    struct timespec t1;
    clock_gettime(CLOCK_REALTIME, &t1);
    for (i=0; i<NUM_ITER; i++)
        success &= ntru_encrypt((char*)&plain, strlen(plain), &kp.pub, &params, dev_urandom, (char*)&encrypted) == 0;
    struct timespec t2;
    clock_gettime(CLOCK_REALTIME, &t2);
    double time = (1000000000.0*(t2.tv_sec-t1.tv_sec)+t2.tv_nsec-t1.tv_nsec) / NUM_ITER;
    double per_sec = 1000000000.0 / time;
    printf("%f encryptions/sec\n", per_sec);

    int dec_len;
    clock_gettime(CLOCK_REALTIME, &t1);
    for (i=0; i<NUM_ITER; i++)
        success &= ntru_decrypt((char*)&encrypted, &kp, &params, (unsigned char*)&decrypted, &dec_len) == 0;
    clock_gettime(CLOCK_REALTIME, &t2);
    time = (1000000000.0*(t2.tv_sec-t1.tv_sec)+t2.tv_nsec-t1.tv_nsec) / NUM_ITER;
    per_sec = 1000000000.0 / time;
    printf("%f decryptions/sec\n", per_sec);

    if (!success)
        printf("Error!\n");
    return success ? 0 : 1;
}
