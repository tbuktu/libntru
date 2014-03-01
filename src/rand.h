#ifndef RAND_H
#define RAND_H

/**
 * Seed and state for deterministic random number generators
 */
typedef struct NtruRandContext {
    char *seed;
    int seed_len;
    void **rand_state;
} NtruRandContext;

#ifdef WIN32

/**
 * @brief CryptGenRandom-based RNG
 *
 * Fills an array with random data from CryptGenRandom().
 *
 * @param rand_data output parameter; the random data is written to this array
 * @param len the number of elements to write to rand_data
 * @param rand_ctx ignored
 * @return 0 for error, 1 otherwise
 */
int ntru_rand_wincrypt(unsigned rand_data[], int len, struct NtruRandContext *rand_ctx);

#else

/**
 * @brief /dev/random-based RNG
 *
 * Fills an array with random data from /dev/random.
 *
 * @param rand_data output parameter; the random data is written to this array
 * @param len the number of elements to write to rand_data
 * @param rand_ctx ignored
 * @return 0 for error, 1 otherwise
 */
int ntru_rand_devrandom(unsigned rand_data[], int len, NtruRandContext *rand_ctx);

/**
 * @brief /dev/urandom-based RNG
 *
 * Fills an array with random data from /dev/urandom.
 *
 * @param rand_data output parameter; the random data is written to this array
 * @param len the number of elements to write to rand_data
 * @param rand_ctx ignored
 * @return 0 for error, 1 otherwise
 */
int ntru_rand_devurandom(unsigned rand_data[], int len, NtruRandContext *rand_ctx);
#endif // WIN32

/**
 * @brief default RNG
 *
 * Fills an array with random data from CryptGenRandom() (on Windows) or
 * /dev/urandom (on *nix).
 *
 * @param rand_data output parameter; the random data is written to this array
 * @param len the number of elements to write to rand_data
 * @param rand_ctx ignored
 * @return 0 for error, 1 otherwise
 */
int ntru_rand_default(unsigned rand_data[], int len, NtruRandContext *rand_ctx);

/**
 * @brief deterministic RNG based on IGF-2
 *
 * Fills an array with random data from ntru_IGF_next()
 *
 * @param rand_data output parameter; the random data is written to this array
 * @param len the number of elements to write to rand_data
 * @param rand_ctx pointer to a NtruRandContext struct
 * @return 0 for error, 1 otherwise
 */
int ntru_rand_igf2(unsigned rand_data[], int len, NtruRandContext *rand_ctx);

#endif   /* RAND_H */
