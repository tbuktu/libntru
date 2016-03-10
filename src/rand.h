#ifndef NTRU_RAND_H
#define NTRU_RAND_H

#include "types.h"

struct NtruRandGen;
typedef struct NtruRandContext {
    struct NtruRandGen *rand_gen;
    uint8_t *seed;       /* for deterministic RNGs */
    uint16_t seed_len;   /* for deterministic RNGs */
    void *state;
} NtruRandContext;

typedef struct NtruRandGen {
    uint8_t (*init)(NtruRandContext *rand_ctx, struct NtruRandGen *rand_gen);
    /* a pointer to a function that takes an array and an array size, and fills the array with random data */
    uint8_t (*generate)(uint8_t rand_data[], uint16_t len, NtruRandContext *rand_ctx);
    uint8_t (*release)(NtruRandContext *rand_ctx);
} NtruRandGen;

/** Returns NTRU_SUCCESS or NTRU_ERR_PRNG */
uint8_t ntru_rand_init(NtruRandContext *rand_ctx, struct NtruRandGen *rand_gen);

/** Returns NTRU_SUCCESS or NTRU_ERR_PRNG */
uint8_t ntru_rand_init_det(NtruRandContext *rand_ctx, struct NtruRandGen *rand_gen, uint8_t *seed, uint16_t seed_len);

/** Returns NTRU_SUCCESS or NTRU_ERR_PRNG */
uint8_t ntru_rand_generate(uint8_t rand_data[], uint16_t len, NtruRandContext *rand_ctx);

/** Returns NTRU_SUCCESS or NTRU_ERR_PRNG */
uint8_t ntru_rand_release(NtruRandContext *rand_ctx);

#ifdef WIN32

#define NTRU_RNG_WINCRYPT {ntru_rand_wincrypt_init, ntru_rand_wincrypt_generate, ntru_rand_wincrypt_release}

/* CryptGenRandom-based RNG */
uint8_t ntru_rand_wincrypt_init(NtruRandContext *rand_ctx, NtruRandGen *rand_gen);
uint8_t ntru_rand_wincrypt_generate(uint8_t rand_data[], uint16_t len, NtruRandContext *rand_ctx);
uint8_t ntru_rand_wincrypt_release(NtruRandContext *rand_ctx);

#else

#define NTRU_RNG_DEVURANDOM {ntru_rand_devurandom_init, ntru_rand_devurandom_generate, ntru_rand_devurandom_release}
#define NTRU_RNG_DEVRANDOM {ntru_rand_devrandom_init, ntru_rand_devrandom_generate, ntru_rand_devrandom_release}

/* /dev/random-based RNG */
uint8_t ntru_rand_devrandom_init(NtruRandContext *rand_ctx, struct NtruRandGen *rand_gen);
uint8_t ntru_rand_devrandom_generate(uint8_t rand_data[], uint16_t len, NtruRandContext *rand_ctx);
uint8_t ntru_rand_devrandom_release(NtruRandContext *rand_ctx);

/* /dev/urandom-based RNG */
uint8_t ntru_rand_devurandom_init(NtruRandContext *rand_ctx, struct NtruRandGen *rand_gen);
uint8_t ntru_rand_devurandom_generate(uint8_t rand_data[], uint16_t len, NtruRandContext *rand_ctx);
uint8_t ntru_rand_devurandom_release(NtruRandContext *rand_ctx);

#endif /* !WIN32 */

/** default RNG: CTR_DRBG seeded from /dev/urandom (on *nix) or CryptGenRandom() (on Windows) */
uint8_t ntru_rand_default_init(NtruRandContext *rand_ctx, struct NtruRandGen *rand_gen);
uint8_t ntru_rand_default_generate(uint8_t rand_data[], uint16_t len, NtruRandContext *rand_ctx);
uint8_t ntru_rand_default_release(NtruRandContext *rand_ctx);
#define NTRU_RNG_DEFAULT {ntru_rand_default_init, ntru_rand_default_generate, ntru_rand_default_release}

/* deterministic RNG based on CTR_DRBG */
uint8_t ntru_rand_ctr_drbg_init(NtruRandContext *rand_ctx, struct NtruRandGen *rand_gen);
uint8_t ntru_rand_ctr_drbg_generate(uint8_t rand_data[], uint16_t len, NtruRandContext *rand_ctx);
uint8_t ntru_rand_ctr_drbg_release(NtruRandContext *rand_ctx);
#define NTRU_RNG_CTR_DRBG {ntru_rand_ctr_drbg_init, ntru_rand_ctr_drbg_generate, ntru_rand_ctr_drbg_release}

#endif   /* NTRU_RAND_H */
