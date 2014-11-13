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

uint8_t ntru_rand_init(NtruRandContext *rand_ctx, struct NtruRandGen *rand_gen) {
    rand_ctx->rand_gen = rand_gen;
    return rand_gen->init(rand_ctx, rand_gen);
}

uint8_t ntru_rand_init_det(NtruRandContext *rand_ctx, struct NtruRandGen *rand_gen, uint8_t *seed, uint16_t seed_len) {
    rand_ctx->seed = seed;
    rand_ctx->seed_len = seed_len;
    rand_ctx->rand_gen = rand_gen;
    return rand_gen->init(rand_ctx, rand_gen);
}

uint8_t ntru_rand_generate(uint8_t rand_data[], uint16_t len, NtruRandContext *rand_ctx) {
    return rand_ctx->rand_gen->generate(rand_data, len, rand_ctx);
}

uint8_t ntru_rand_release(NtruRandContext *rand_ctx) {
    return rand_ctx->rand_gen->release(rand_ctx);
}

#ifdef WIN32
uint8_t ntru_rand_wincrypt_init(NtruRandContext *rand_ctx) {
    HCRYPTPROV *hCryptProv = malloc(sizeof hCryptProv);
    if (hCryptProv == NULL)
        return 0;
    uint8_t result = CryptAcquireContext(hCryptProv, NULL, NULL, PROV_RSA_FULL, 0);
    if (!result) {
        if (GetLastError() == (DWORD)NTE_BAD_KEYSET)   // see http://support.microsoft.com/kb/238187
            result = CryptAcquireContext(hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_NEWKEYSET);
        if (!result)
            return 0;
    }
    rand_ctx->rand_state = hCryptProv;
    return 1;
}

uint8_t ntru_rand_wincrypt_generate(uint8_t rand_data[], uint16_t len, NtruRandContext *rand_ctx) {
    HCRYPTPROV *hCryptProv = (HCRYPTPROV)rand_ctx->rand_state;
    if (hCryptProv==NULL && !ntru_rand_wincrypt_init(rand_ctx))
        return 0;
    return CryptGenRandom(hCryptProv, len, rand_data);
}

uint8_t ntru_rand_wincrypt_release(NtruRandContext *rand_ctx) {
    HCRYPTPROV *hCryptProv = (HCRYPTPROV)rand_ctx->rand_state;
    uint8_t result = CryptReleaseContext(hCryptProv, 0);
    free(hCryptProv);
    return result;
}

NtruRandGen NTRU_RNG_WINCRYPT = {ntru_rand_wincrypt_init, ntru_rand_wincrypt_generate, ntru_rand_wincrypt_release};
NtruRandGen NTRU_RNG_DEFAULT = NTRU_RNG_WINCRYPT;
#else

uint8_t ntru_rand_devurandom_init(NtruRandContext *rand_ctx, struct NtruRandGen *rand_gen) {
    return 1;
}

uint8_t ntru_rand_devurandom_generate(uint8_t rand_data[], uint16_t len, NtruRandContext *rand_ctx) {
    int rand_fd = open("/dev/urandom", O_RDONLY);
    if (rand_fd < 0)
        return 0;
    ssize_t bytes_read = read(rand_fd, rand_data, len);
    close(rand_fd);
    return bytes_read == len;
}

uint8_t ntru_rand_devurandom_release(NtruRandContext *rand_ctx) {
    return 1;
}
#endif // WIN32

uint8_t ntru_rand_igf2_init(NtruRandContext *rand_ctx, struct NtruRandGen *rand_gen) {
    rand_ctx->state = malloc(sizeof(struct NtruIGFState));
    if (!rand_ctx->state)
        return 0;
    NtruEncParams params = EES401EP1;
    params.N = 256;   /* we want to generate bytes */
    ntru_IGF_init(rand_ctx->seed, rand_ctx->seed_len, &params, rand_ctx->state);
    return 1;
}

uint8_t ntru_rand_igf2_generate(uint8_t rand_data[], uint16_t len, NtruRandContext *rand_ctx) {
    uint16_t i;
    for (i=0; i<len; i++) {
        uint16_t idx;
        ntru_IGF_next(rand_ctx->state, &idx);
        rand_data[i] = idx;
    }
    return 1;
}

uint8_t ntru_rand_igf2_release(NtruRandContext *rand_ctx) {
    return 1;
}
