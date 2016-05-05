#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include "rand.h"
#include "err.h"
#include "encparams.h"
#include "nist_ctr_drbg.h"
#ifdef WIN32
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <Wincrypt.h>
#endif

const char NTRU_PERS_STRING[] = "libntru";   /* personalization string for CTR-DRBG */

uint8_t ntru_rand_init(NtruRandContext *rand_ctx, struct NtruRandGen *rand_gen) {
    rand_ctx->rand_gen = rand_gen;
    rand_ctx->seed = NULL;
    return rand_gen->init(rand_ctx, rand_gen) ? NTRU_SUCCESS : NTRU_ERR_PRNG;
}

uint8_t ntru_rand_init_det(NtruRandContext *rand_ctx, struct NtruRandGen *rand_gen, uint8_t *seed, uint16_t seed_len) {
    rand_ctx->seed = malloc(seed_len);
    if (rand_ctx->seed == NULL)
        return NTRU_ERR_PRNG;
    memcpy(rand_ctx->seed, seed, seed_len);
    rand_ctx->seed_len = seed_len;
    rand_ctx->rand_gen = rand_gen;
    return rand_gen->init(rand_ctx, rand_gen) ? NTRU_SUCCESS : NTRU_ERR_PRNG;
}

uint8_t ntru_rand_generate(uint8_t rand_data[], uint16_t len, NtruRandContext *rand_ctx) {
    return rand_ctx->rand_gen->generate(rand_data, len, rand_ctx) ? NTRU_SUCCESS : NTRU_ERR_PRNG;
}

uint8_t ntru_rand_release(NtruRandContext *rand_ctx) {
    if (rand_ctx->seed != NULL)
        free(rand_ctx->seed);
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
        if (fd_ptr == NULL) {
            close(rand_fd);
            return 0;
        }
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

uint8_t ntru_rand_ctr_drbg_init(NtruRandContext *rand_ctx, struct NtruRandGen *rand_gen) {
    rand_ctx->state = malloc(sizeof(NIST_CTR_DRBG));
    if (!rand_ctx->state)
        return 0;
    uint16_t pers_string_size = strlen(NTRU_PERS_STRING) * sizeof(NTRU_PERS_STRING[0]);
    return nist_ctr_drbg_instantiate(rand_ctx->state, rand_ctx->seed, rand_ctx->seed_len, NULL, 0, NTRU_PERS_STRING, pers_string_size) == 0;
}

uint8_t ntru_rand_ctr_drbg_generate(uint8_t rand_data[], uint16_t len, NtruRandContext *rand_ctx) {
    nist_ctr_drbg_generate(rand_ctx->state, rand_data, len, NULL, 0);
    return 1;
}

uint8_t ntru_rand_ctr_drbg_release(NtruRandContext *rand_ctx) {
    uint8_t result = nist_ctr_drbg_destroy(rand_ctx->state);
    free(rand_ctx->state);
    return result;
}

uint8_t ntru_get_entropy(uint8_t *buffer, uint16_t len) {
#ifdef WIN32
    /* initialize */
    HCRYPTPROV hCryptProv;
    uint8_t result = CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, 0);
    if (!result) {
        if (GetLastError() == (DWORD)NTE_BAD_KEYSET)   /* see http://support.microsoft.com/kb/238187 */
            result = CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_NEWKEYSET);
        if (!result)
            return 0;
    }

    /* generate */
    result &= CryptGenRandom(hCryptProv, len, buffer);

    /* release */
    result &= CryptReleaseContext(hCryptProv, 0);
    return result;
#else
    /* open /dev/urandom */
    int rand_fd = open("/dev/urandom", O_RDONLY);
    uint8_t result = rand_fd >= 0;

    /* read */
    ssize_t bytes_read = read(rand_fd, buffer, len);
    result &= bytes_read == len;

    /* close */
    result &= close(rand_fd) >= 0;
    return result;
#endif /* !WIN32 */
}

uint8_t ntru_rand_default_init(NtruRandContext *rand_ctx, struct NtruRandGen *rand_gen) {
    uint8_t result = 1;
    result &= nist_ctr_initialize() == 0;
    rand_ctx->state = malloc(sizeof(NIST_CTR_DRBG));
    if (!rand_ctx->state)
        return 0;
    uint8_t entropy[32];
    result &= ntru_get_entropy(entropy, 32);
    uint16_t pers_string_size = strlen(NTRU_PERS_STRING) * sizeof(NTRU_PERS_STRING[0]);
    result &= nist_ctr_drbg_instantiate(rand_ctx->state, entropy, 32, NULL, 0, NTRU_PERS_STRING, pers_string_size) == 0;
    return result;
}

uint8_t ntru_rand_default_generate(uint8_t rand_data[], uint16_t len, NtruRandContext *rand_ctx) {
    nist_ctr_drbg_generate(rand_ctx->state, rand_data, len, NULL, 0);
    return 1;
}

uint8_t ntru_rand_default_release(NtruRandContext *rand_ctx) {
    uint8_t result = nist_ctr_drbg_destroy(rand_ctx->state);
    free(rand_ctx->state);
    return result;
}
