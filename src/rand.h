#ifndef RAND_H
#define RAND_H

#ifdef WIN32

/**
 * @brief CryptGenRandom-based RNG
 *
 * Fills an array with random data from CryptGenRandom().
 *
 * @param rand_data output parameter; the random data is written to this array
 * @param len the number of elements to write to rand_data
 * @return 0 for error, 1 otherwise
 */
int ntru_rand_wincrypt(unsigned rand_data[], int len);

#else

/**
 * @brief /dev/random-based RNG
 *
 * Fills an array with random data from /dev/random.
 *
 * @param rand_data output parameter; the random data is written to this array
 * @param len the number of elements to write to rand_data
 * @return 0 for error, 1 otherwise
 */
int ntru_rand_devrandom(unsigned rand_data[], int len);

/**
 * @brief /dev/urandom-based RNG
 *
 * Fills an array with random data from /dev/urandom.
 *
 * @param rand_data output parameter; the random data is written to this array
 * @param len the number of elements to write to rand_data
 * @return 0 for error, 1 otherwise
 */
int ntru_rand_devurandom(unsigned rand_data[], int len);
#endif // WIN32

/**
 * @brief default RNG
 *
 * Fills an array with random data from CryptGenRandom() (on Windows) or
 * /dev/urandom (on *nix).
 *
 * @param rand_data output parameter; the random data is written to this array
 * @param len the number of elements to write to rand_data
 * @return 0 for error, 1 otherwise
 */
int ntru_rand_default(unsigned rand_data[], int len);

#endif   /* RAND_H */
