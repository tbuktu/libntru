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
void ntru_MGF(char *seed, int seed_len, struct NtruEncParams *params, NtruIntPoly *i);
