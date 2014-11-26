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

uint8_t ntru_rand_init(NtruRandContext *rand_ctx, struct NtruRandGen *rand_gen);
uint8_t ntru_rand_init_det(NtruRandContext *rand_ctx, struct NtruRandGen *rand_gen, uint8_t *seed, uint16_t seed_len);
uint8_t ntru_rand_generate(uint8_t rand_data[], uint16_t len, NtruRandContext *rand_ctx);
uint8_t ntru_rand_release(NtruRandContext *rand_ctx);

#ifdef WIN32

#define NTRU_RNG_WINCRYPT {ntru_rand_wincrypt_init, ntru_rand_wincrypt_generate, ntru_rand_wincrypt_release}
/** default RNG (CryptGenRandom() on Windows) */
#define NTRU_RNG_DEFAULT NTRU_RNG_WINCRYPT

/* CryptGenRandom-based RNG */
uint8_t ntru_rand_wincrypt_init(NtruRandContext *rand_ctx, NtruRandGen *rand_gen);
uint8_t ntru_rand_wincrypt_generate(uint8_t rand_data[], uint16_t len, NtruRandContext *rand_ctx);
uint8_t ntru_rand_wincrypt_release(NtruRandContext *rand_ctx);

#else

#define NTRU_RNG_DEVURANDOM {ntru_rand_devurandom_init, ntru_rand_devurandom_generate, ntru_rand_devurandom_release}
#define NTRU_RNG_DEVRANDOM {ntru_rand_devrandom_init, ntru_rand_devrandom_generate, ntru_rand_devrandom_release}
/** default RNG (/dev/urandom on *nix) */
#define NTRU_RNG_DEFAULT NTRU_RNG_DEVURANDOM

/* /dev/random-based RNG */
uint8_t ntru_rand_devrandom_init(NtruRandContext *rand_ctx, struct NtruRandGen *rand_gen);
uint8_t ntru_rand_devrandom_generate(uint8_t rand_data[], uint16_t len, NtruRandContext *rand_ctx);
uint8_t ntru_rand_devrandom_release(NtruRandContext *rand_ctx);

/* /dev/urandom-based RNG */
uint8_t ntru_rand_devurandom_init(NtruRandContext *rand_ctx, struct NtruRandGen *rand_gen);
uint8_t ntru_rand_devurandom_generate(uint8_t rand_data[], uint16_t len, NtruRandContext *rand_ctx);
uint8_t ntru_rand_devurandom_release(NtruRandContext *rand_ctx);

#endif // !WIN32

/* deterministic RNG based on IGF-2 */
uint8_t ntru_rand_igf2_init(NtruRandContext *rand_ctx, struct NtruRandGen *rand_gen);
uint8_t ntru_rand_igf2_generate(uint8_t rand_data[], uint16_t len, NtruRandContext *rand_ctx);
uint8_t ntru_rand_igf2_release(NtruRandContext *rand_ctx);

#define NTRU_RNG_IGF2 {ntru_rand_igf2_init, ntru_rand_igf2_generate, ntru_rand_igf2_release}

#endif   /* NTRU_RAND_H */
