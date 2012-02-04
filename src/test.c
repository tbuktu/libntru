#include <stdio.h>
#include "test_poly.h"

int main(int argc, char** argv) {
    printf("Running tests...\n");
    int pass = test_poly();
    printf("%s\n", pass?"All tests passed":"One or more tests failed");
    return pass ? 0 : 1;
}
