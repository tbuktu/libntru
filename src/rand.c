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

const NtruEncParams NTRU_IGF2_RAND_PARAMS = {\
    "EES401EP1",   /* name */\
    401,           /* N */\
    256,           /* q=256 because we want to generate bytes */\
    0,             /* prod_flag */\
    0,             /* df */\
    0,\
    0,\
    0,             /* dm0 */\
    0,             /* db */\
    11,            /* c */\
    0,             /* min_calls_r */\
    0,             /* min_calls_mask */\
    1,             /* hash_seed */\
    {0, 0, 0},     /* oid */\
    ntru_sha1,     /* hash */\
    ntru_sha1_4way, /* hash_4way */\
    20,            /* hlen */\
    0              /* pklen */\
};

uint8_t ntru_rand_init(NtruRandContext *rand_ctx, struct NtruRandGen *rand_gen) {
    rand_ctx->rand_gen = rand_gen;
    return rand_gen->init(rand_ctx, rand_gen) ? NTRU_SUCCESS : NTRU_ERR_PRNG;
}

uint8_t ntru_rand_init_det(NtruRandContext *rand_ctx, struct NtruRandGen *rand_gen, uint8_t *seed, uint16_t seed_len) {
    rand_ctx->seed = seed;
    rand_ctx->seed_len = seed_len;
    rand_ctx->rand_gen = rand_gen;
    return rand_gen->init(rand_ctx, rand_gen) ? NTRU_SUCCESS : NTRU_ERR_PRNG;
}

uint8_t ntru_rand_generate(uint8_t rand_data[], uint16_t len, NtruRandContext *rand_ctx) {
    return rand_ctx->rand_gen->generate(rand_data, len, rand_ctx) ? NTRU_SUCCESS : NTRU_ERR_PRNG;
}

uint8_t ntru_rand_release(NtruRandContext *rand_ctx) {
    return rand_ctx->rand_gen->release(rand_ctx) ? NTRU_SUCCESS : NTRU_ERR_PRNG;
}

#ifdef WIN32
uint8_t ntru_rand_wincrypt_init(NtruRandContext *rand_ctx, NtruRandGen *rand_gen) {
    HCRYPTPROV *hCryptProv = malloc(sizeof(HCRYPTPROV));
    if (hCryptProv == NULL)
        return 0;
    uint8_t result = CryptAcquireContext(hCryptProv, NULL, NULL, PROV_RSA_FULL, 0);
    if (!result) {
        if (GetLastError() == (DWORD)NTE_BAD_KEYSET)   /* see http://support.microsoft.com/kb/238187 */
            result = CryptAcquireContext(hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_NEWKEYSET);
        if (!result) {
            free(hCryptProv);
            return 0;
        }
    }
    rand_ctx->state = hCryptProv;
    return 1;
}

uint8_t ntru_rand_wincrypt_generate(uint8_t rand_data[], uint16_t len, NtruRandContext *rand_ctx) {
    HCRYPTPROV *hCryptProv = (HCRYPTPROV*)rand_ctx->state;
    return CryptGenRandom(*hCryptProv, len, rand_data);
}

uint8_t ntru_rand_wincrypt_release(NtruRandContext *rand_ctx) {
    HCRYPTPROV *hCryptProv = (HCRYPTPROV*)rand_ctx->state;
    uint8_t result = CryptReleaseContext(*hCryptProv, 0);
    free(hCryptProv);
    return result;
}

#else

uint8_t ntru_rand_device_init(NtruRandContext *rand_ctx, struct NtruRandGen *rand_gen, char *filename) {
    int rand_fd = open(filename, O_RDONLY);
    if (rand_fd >= 0) {
        /* save rand_fd in rand_ctx->state */
        int *fd_ptr = malloc(sizeof(int));
        if (fd_ptr == NULL)
            return 0;
        *fd_ptr = rand_fd;
        rand_ctx->state = fd_ptr;
    }
    return rand_fd >= 0;
}

uint8_t ntru_rand_device_generate(uint8_t rand_data[], uint16_t len, NtruRandContext *rand_ctx) {
    int rand_fd = *((int*)rand_ctx->state);
    ssize_t bytes_read = read(rand_fd, rand_data, len);
    return bytes_read == len;
}

uint8_t ntru_rand_device_release(NtruRandContext *rand_ctx) {
    int rand_fd = *((int*)rand_ctx->state);
    free(rand_ctx->state);
    return close(rand_fd) >= 0;
}

uint8_t ntru_rand_devurandom_init(NtruRandContext *rand_ctx, struct NtruRandGen *rand_gen) {
    return ntru_rand_device_init(rand_ctx, rand_gen, "/dev/urandom");
}

uint8_t ntru_rand_devurandom_generate(uint8_t rand_data[], uint16_t len, NtruRandContext *rand_ctx) {
    return ntru_rand_device_generate(rand_data, len, rand_ctx);
}

uint8_t ntru_rand_devurandom_release(NtruRandContext *rand_ctx) {
    return ntru_rand_device_release(rand_ctx);
}

uint8_t ntru_rand_devrandom_init(NtruRandContext *rand_ctx, struct NtruRandGen *rand_gen) {
    return ntru_rand_device_init(rand_ctx, rand_gen, "/dev/random");
}

uint8_t ntru_rand_devrandom_generate(uint8_t rand_data[], uint16_t len, NtruRandContext *rand_ctx) {
    return ntru_rand_device_generate(rand_data, len, rand_ctx);
}

uint8_t ntru_rand_devrandom_release(NtruRandContext *rand_ctx) {
    return ntru_rand_device_release(rand_ctx);
}
#endif /* !WIN32 */

uint8_t ntru_rand_igf2_init(NtruRandContext *rand_ctx, struct NtruRandGen *rand_gen) {
    rand_ctx->state = malloc(sizeof(struct NtruIGFState));
    if (!rand_ctx->state)
        return 0;
    ntru_IGF_init(rand_ctx->seed, rand_ctx->seed_len, &NTRU_IGF2_RAND_PARAMS, rand_ctx->state);
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
    free(rand_ctx->state);
    return 1;
}
