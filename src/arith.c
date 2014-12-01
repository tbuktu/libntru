#include "arith.h"

uint8_t ntru_log2(uint16_t n) {
    uint8_t log = 0;
    while (n > 1) {
        n /= 2;
        log++;
    }
    return log;
}
