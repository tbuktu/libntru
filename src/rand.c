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
uint8_t ntru_rand_wincrypt(uint8_t rand_data[], uint16_t len, NtruRandContext *rand_ctx) {
    static HCRYPTPROV hCryptProv = 0;
    if (hCryptProv == 0) {
        uint8_t result = CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, 0);
        if (!result) {
            if (GetLastError() == NTE_BAD_KEYSET)   // see http://support.microsoft.com/kb/238187
                result = CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_NEWKEYSET);
            if (!result)
                return 0;
        }
    }
    return CryptGenRandom(hCryptProv, len, rand_data);
}

uint8_t ntru_rand_default(uint8_t rand_data[], uint16_t len, NtruRandContext *rand_ctx) {
    return ntru_rand_wincrypt(rand_data, len, rand_ctx);
}

#else

uint8_t ntru_rand_devrandom(uint8_t rand_data[], uint16_t len, NtruRandContext *rand_ctx) {
    int rand_fd = open("/dev/random", O_RDONLY);
    if (rand_fd < 0)
        return 0;
    uint16_t tot_bytes = 0;
    while (tot_bytes < len) {
        ssize_t bytes_read = read(rand_fd, ((uint8_t*)rand_data)+tot_bytes, len-tot_bytes);
        if (bytes_read <= 0)
            return 0;
        tot_bytes += bytes_read;
    }
    close(rand_fd);
    return tot_bytes == len;
}

uint8_t ntru_rand_devurandom(uint8_t rand_data[], uint16_t len, NtruRandContext *rand_ctx) {
    int rand_fd = open("/dev/urandom", O_RDONLY);
    if (rand_fd < 0)
        return 0;
    ssize_t bytes_read = read(rand_fd, rand_data, len);
    close(rand_fd);
    return bytes_read == len;
}

uint8_t ntru_rand_default(uint8_t rand_data[], uint16_t len, NtruRandContext *rand_ctx) {
    return ntru_rand_devurandom(rand_data, len, rand_ctx);
}
#endif // WIN32

uint8_t ntru_rand_igf2(uint8_t rand_data[], uint16_t len, NtruRandContext *rand_ctx) {
    NtruIGFState *igf_state;
    if (*(rand_ctx->rand_state) == NULL) {
        *(rand_ctx->rand_state) = (NtruIGFState*)malloc(sizeof *igf_state);
        NtruEncParams params = EES439EP1;
        params.N = 256;   /* we want to generate bytes */
        ntru_IGF_init(rand_ctx->seed, rand_ctx->seed_len, &params, (NtruIGFState*)*(rand_ctx->rand_state));
    }

    igf_state = (NtruIGFState*)*(rand_ctx->rand_state);
    uint16_t i;
    for (i=0; i<len; i++) {
        uint16_t idx;
        ntru_IGF_next(igf_state, &idx);
        rand_data[i] = idx;
    }
    return 1;
}
