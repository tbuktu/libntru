#include <stdio.h>
#include "test_poly.h"
#include "test_ntruencrypt.h"
#include "test_idxgen.h"
#include "test_bitstring.h"

int main(int argc, char** argv) {
    printf("Running tests...\n");
    int pass = test_poly();
    pass &= test_ntruencrypt();
    pass &= test_idxgen();
    pass &= test_bitstring();
    printf("%s\n", pass?"All tests passed":"One or more tests failed");
    return pass ? 0 : 1;
}
