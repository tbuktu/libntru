#include <stdlib.h>
#include <time.h>
#include <math.h>
#include <string.h>
#include "encparams.h"
#include "idxgen.h"
#include "test_util.h"

/** number of calls to IGF */
#define NUM_ITER 1000
#define NUM_ITER_LARGE 100000

/* tests the IGF-2 implementation */
uint8_t test_idxgen() {
    /* seed random number generator */
    time_t rs;
    time(&rs);
    srand(rs);

    /* generate a random IGF seed array */
    uint32_t i;
    uint8_t seed[100];
    for (i=0; i<sizeof seed; i++)
        seed[i] = rand();

#ifndef NTRU_AVOID_HAMMING_WT_PATENT
    NtruEncParams params[] = {EES743EP1, EES1087EP2};
#else
    NtruEncParams params[] = {EES1087EP2};
#endif   /* NTRU_AVOID_HAMMING_WT_PATENT */
    uint8_t valid = 1;
    for (i=0; i<sizeof(params)/sizeof(params[0]); i++) {
        double avg = 0;
        NtruIGFState s;

        /* sanity check for the avg value */
        ntru_IGF_init(seed, sizeof seed, &params[i], &s);
        uint16_t idx;
        uint32_t j;
        for (j=0; j<NUM_ITER; j++) {
            ntru_IGF_next(&s, &idx);
            avg += idx;
        }
        avg /= NUM_ITER;

        valid &= fabs((params[i].N/2.0)-avg) < 30;

        /* test reproducability */
        ntru_IGF_init(seed, sizeof seed, &params[i], &s);
        uint16_t last_idx = idx;
        for (j=0; j<NUM_ITER; j++)
            ntru_IGF_next(&s, &idx);
        valid &= idx == last_idx;

        /* check that all values between 0 and N-1 are generated */
        ntru_IGF_init(seed, sizeof seed, &params[i], &s);
        uint8_t checklist[params[i].N];
        memset(checklist, 0, params[i].N);
        for (j=0; j<NUM_ITER_LARGE; j++) {
            ntru_IGF_next(&s, &idx);
            checklist[idx] = 1;
        }
        for (j=0; j<params[i].N; j++)
            valid &= checklist[j];
    }

    print_result("test_idxgen", valid);
    return valid;
}
