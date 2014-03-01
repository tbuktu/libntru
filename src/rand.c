#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include "rand.h"
#include "err.h"
#include "encparams.h"
#include "idxgen.h"
#ifdef WIN32
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <Wincrypt.h>
#endif

#ifdef WIN32
int ntru_rand_wincrypt(unsigned rand_data[], int len, NtruRandContext *rand_ctx) {
    static HCRYPTPROV hCryptProv = NULL;
    if (hCryptProv == NULL) {
        int result = CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, 0);
        if (!result) {
            if (GetLastError() == NTE_BAD_KEYSET)   // see http://support.microsoft.com/kb/238187
                result = CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_NEWKEYSET);
            if (!result)
                return NTRU_ERR_PRNG;
        }
    }
    return CryptGenRandom(hCryptProv, len * sizeof *rand_data, rand_data);
}

int ntru_rand_default(unsigned rand_data[], int len, NtruRandContext *rand_ctx) {
    return ntru_rand_wincrypt(rand_data, len, rand_ctx);
}

#else

int ntru_rand_devrandom(unsigned rand_data[], int len, NtruRandContext *rand_ctx) {
    int rand_fd = open("/dev/random", O_RDONLY);
    if (rand_fd < 0)
        return 0;
    int tot_bytes = 0;
    unsigned len_bytes = len * (sizeof rand_data[0]);
    while (tot_bytes < len_bytes) {
        int bytes_read = read(rand_fd, ((char*)rand_data)+tot_bytes, len_bytes-tot_bytes);
        if (bytes_read <= 0)
            return 0;
        tot_bytes += bytes_read;
    }
    close(rand_fd);
    return tot_bytes == len_bytes;
}

int ntru_rand_devurandom(unsigned rand_data[], int len, NtruRandContext *rand_ctx) {
    int rand_fd = open("/dev/urandom", O_RDONLY);
    if (rand_fd < 0)
        return 0;
    int bytes_read = read(rand_fd, rand_data, len * sizeof *rand_data);
    close(rand_fd);
    return bytes_read == len * sizeof rand_data[0];
}

int ntru_rand_default(unsigned rand_data[], int len, NtruRandContext *rand_ctx) {
    return ntru_rand_devurandom(rand_data, len, rand_ctx);
}
#endif // WIN32

int ntru_rand_igf2(unsigned rand_data[], int len, NtruRandContext *rand_ctx) {
    struct NtruIGFState *igf_state;
    if (*(rand_ctx->rand_state) == NULL) {
        *(rand_ctx->rand_state) = (struct NtruIGFState*)malloc(sizeof *igf_state);
        struct NtruEncParams params = APR2011_439_FAST;
        params.N = 256;   /* we want to generate chars */
        ntru_IGF_init(rand_ctx->seed, rand_ctx->seed_len, &params, (struct NtruIGFState*)*(rand_ctx->rand_state));
    }

    igf_state = (struct NtruIGFState*)*(rand_ctx->rand_state);
    int i;
    for (i=0; i<len; i++) {
        int idx1, idx2, idx3, idx4;
        ntru_IGF_next(igf_state, &idx1);
        ntru_IGF_next(igf_state, &idx2);
        ntru_IGF_next(igf_state, &idx3);
        ntru_IGF_next(igf_state, &idx4);
        rand_data[i] = idx1 + (idx2<<8) + (idx3<<16) + (idx4<<24);
    }
    return 1;
}
