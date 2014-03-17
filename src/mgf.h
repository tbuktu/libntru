#ifndef NTRU_MGF_H
#define NTRU_MGF_H

#include <stdint.h>

/**
 * @brief Mask Generation Function
 *
 * An implementation of MGF-TP-1 from P1363.1 section 8.4.1.1.
 *
 * @param seed seed for the deterministic random number generator
 * @param seed_len length of seed
 * @param params NTRUEncrypt parameters
 * @param i output parameter: the generated ternary polynomial
 */
void ntru_MGF(uint8_t *seed, uint16_t seed_len, NtruEncParams *params, NtruIntPoly *i);

#endif   /* NTRU_MGF_H */
