#include <stdio.h>
#include <stdint.h>
#include "test_poly.h"
#include "test_ntruprime.h"
#include "test_ntru.h"
#include "test_idxgen.h"
#include "test_bitstring.h"
#include "test_key.h"
#include "test_hash.h"

void ntru_set_optimized_impl();

int main(int argc, char** argv) {
    printf("Running tests...\n");
    ntru_set_optimized_impl();   /* normally called by the functions in ntru.h */
    uint8_t pass = test_poly();
    pass &= test_ntruprime();
    pass &= test_ntru();
    pass &= test_idxgen();
    pass &= test_bitstring();
    pass &= test_key();
    pass &= test_hash();
    printf("%s\n", pass?"All tests passed":"One or more tests failed");
    return pass ? 0 : 1;
}
