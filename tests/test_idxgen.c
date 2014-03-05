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
int test_idxgen() {
    /* seed random number generator */
    time_t rs;
    time(&rs);
    srand(rs);

    /* generate a random IGF seed array */
    int i;
    char seed[100];
    for (i=0; i<sizeof seed; i++)
        seed[i] = rand();

    NtruEncParams params = APR2011_743_FAST;
    double avg = 0;
    NtruIGFState s;

    /* sanity check for the avg value */
    ntru_IGF_init(seed, sizeof seed, &params, &s);
    int idx;
    for (i=0; i<NUM_ITER; i++) {
        ntru_IGF_next(&s, &idx);
        avg += idx;
    }
    avg /= NUM_ITER;

    int valid = fabs((params.N/2.0)-avg) < 30;

    /* test reproducability */
    ntru_IGF_init(seed, sizeof seed, &params, &s);
    int last_idx = idx;
    for (i=0; i<NUM_ITER; i++)
        ntru_IGF_next(&s, &idx);
    valid &= idx == last_idx;

    /* check that all values between 0 and N-1 are generated */
    ntru_IGF_init(seed, sizeof seed, &params, &s);
    int check_list[params.N];
    memset(check_list, 0, params.N * sizeof check_list[0]);
    for (i=0; i<NUM_ITER_LARGE; i++) {
        ntru_IGF_next(&s, &idx);
        check_list[idx] = 1;
    }
    for (i=0; i<params.N; i++)
        valid &= check_list[i];

    print_result("test_idxgen", valid);
    return valid;
}
