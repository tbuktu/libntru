#include <stdlib.h>
#include <time.h>
#include <math.h>
#include "encparams.h"
#include "idxgen.h"
#include "test_util.h"

/** number of calls to IGF */
#define NUM_ITER 1000

/* tests the average of multiple indices */
int test_idxgen() {
    // seed random number generator
    time_t rs;
    time(&rs);
    srand(rs);

    // generate a random IGF seed array
    int i;
    char seed[100];
    for (i=0; i<sizeof seed; i++)
        seed[i] = rand();

    struct NtruEncParams params = APR2011_743_FAST;
    double avg = 0;
    NtruIGFState s;
    ntru_IGF_init(seed, sizeof seed, &params, &s);
    int idx;
    for (i=0; i<NUM_ITER; i++) {
        ntru_IGF_next(&s, &idx);
        avg += idx;
    }
    avg /= NUM_ITER;

    int valid = fabs((params.N/2.0)-avg) < 30;

    print_result("test_idxgen", valid);
    return valid;
}
