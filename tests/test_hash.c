#include "test_util.h"
#include "hash.h"
#include "encparams.h"
#include <string.h>

uint8_t test_hash() {
    char* test_string_char = "The quick brown fox jumps over the lazy dog";
    size_t len = strlen(test_string_char);
    uint8_t test_string[len];
    str_to_uint8(test_string_char, test_string);
    uint8_t sha1[] = {
        0x2f, 0xd4, 0xe1, 0xc6, 0x7a, 0x2d, 0x28, 0xfc, 0xed, 0x84, 0x9e, 0xe1,
        0xbb, 0x76, 0xe7, 0x39, 0x1b, 0x93, 0xeb, 0x12
    };
    uint8_t sha256[] = {
        0xd7, 0xa8, 0xfb, 0xb3, 0x07, 0xd7, 0x80, 0x94, 0x69, 0xca, 0x9a, 0xbc,
        0xb0, 0x08, 0x2e, 0x4f, 0x8d, 0x56, 0x51, 0xe4, 0x6d, 0x3c, 0xdb, 0x76,
        0x2d, 0x02, 0xd0, 0xbf, 0x37, 0xc9, 0xe5, 0x92
    };

    uint8_t hash1[20];
    ntru_sha1(test_string, len, (uint8_t*)&hash1);
    int valid1 = memcmp((uint8_t*)hash1, (uint8_t*)sha1, 20) == 0;

    uint8_t hash256[32];
    ntru_sha256(test_string, len, (uint8_t*)&hash256);
    int valid256 = memcmp((uint8_t*)&hash256, (uint8_t*)&sha256, 32) == 0;

    uint8_t valid = valid1 && valid256;
    print_result("test_hash", valid);
    return valid;
}
