#include <stdio.h>
#include "test_poly.h"
#include "test_ntruencrypt.h"

int main(int argc, char** argv) {
    printf("Running tests...\n");
    int pass = test_poly();
    pass &= test_ntruencrypt();
    printf("%s\n", pass?"All tests passed":"One or more tests failed");
    return pass ? 0 : 1;
}
