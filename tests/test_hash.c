#include <string.h>
#include "test_util.h"
#include "hash.h"
#include "encparams.h"
#include "rand.h"

uint8_t test_hash() {
    char* test_string_char = "The quick brown fox jumps over the lazy dog";
    size_t len = strlen(test_string_char);
    uint8_t test_string[len];
    str_to_uint8(test_string_char, test_string);

    /* test ntru_sha1() */
    uint8_t sha1[] = {
        0x2f, 0xd4, 0xe1, 0xc6, 0x7a, 0x2d, 0x28, 0xfc, 0xed, 0x84, 0x9e, 0xe1,
        0xbb, 0x76, 0xe7, 0x39, 0x1b, 0x93, 0xeb, 0x12
    };
    uint8_t hash1[20];
    ntru_sha1(test_string, len, (uint8_t*)&hash1);
    int valid1 = memcmp((uint8_t*)hash1, (uint8_t*)sha1, 20) == 0;

    /* test ntru_sha1_4way() */
    uint16_t i;
    NtruRandContext rand_ctx;
    NtruRandGen rng = NTRU_RNG_DEFAULT;
    valid1 &= ntru_rand_init(&rand_ctx, &rng) == NTRU_SUCCESS;
    for (i=0; i<100; i++) {
        uint16_t inp_len = i;
        uint8_t test_a[inp_len];
        uint8_t test_b[inp_len];
        uint8_t test_c[inp_len];
        uint8_t test_d[inp_len];
        uint8_t *hash_inp[4];
        hash_inp[0] = test_a;
        hash_inp[1] = test_b;
        hash_inp[2] = test_c;
        hash_inp[3] = test_d;
        uint8_t j;
        for (j=0; j<4; j++)
            valid1 &= ntru_rand_generate(hash_inp[j], inp_len, &rand_ctx) == NTRU_SUCCESS;
        uint8_t H4_arr[4][20];
        uint8_t *H4[4];
        for (j=0; j<4; j++)
            H4[j] = H4_arr[j];
        ntru_sha1_4way(hash_inp, inp_len, H4);
        for (j=0; j<4; j++) {
            uint8_t H1[20];
            ntru_sha1(hash_inp[j], inp_len, H1);
            valid1 &= memcmp(H4[j], H1, 20) == 0;
        }
    }

    /* test ntru_sha1_8way() */
    valid1 &= ntru_rand_init(&rand_ctx, &rng) == NTRU_SUCCESS;
    for (i=0; i<100; i++) {
        uint16_t inp_len = i;
        uint8_t test_a[inp_len];
        uint8_t test_b[inp_len];
        uint8_t test_c[inp_len];
        uint8_t test_d[inp_len];
        uint8_t test_e[inp_len];
        uint8_t test_f[inp_len];
        uint8_t test_g[inp_len];
        uint8_t test_h[inp_len];
        uint8_t *hash_inp[8];
        hash_inp[0] = test_a;
        hash_inp[1] = test_b;
        hash_inp[2] = test_c;
        hash_inp[3] = test_d;
        hash_inp[4] = test_e;
        hash_inp[5] = test_f;
        hash_inp[6] = test_g;
        hash_inp[7] = test_h;
        uint8_t j;
        for (j=0; j<8; j++)
            valid1 &= ntru_rand_generate(hash_inp[j], inp_len, &rand_ctx) == NTRU_SUCCESS;
        uint8_t H8_arr[8][20];
        uint8_t *H8[8];
        for (j=0; j<8; j++)
            H8[j] = H8_arr[j];
        ntru_sha1_8way(hash_inp, inp_len, H8);
        for (j=0; j<8; j++) {
            uint8_t H1[20];
            ntru_sha1(hash_inp[j], inp_len, H1);
            valid1 &= memcmp(H8[j], H1, 20) == 0;
        }
    }
    valid1 &= ntru_rand_release(&rand_ctx) == NTRU_SUCCESS;

    /* test ntru_sha256() */
    uint8_t sha256[] = {
        0xd7, 0xa8, 0xfb, 0xb3, 0x07, 0xd7, 0x80, 0x94, 0x69, 0xca, 0x9a, 0xbc,
        0xb0, 0x08, 0x2e, 0x4f, 0x8d, 0x56, 0x51, 0xe4, 0x6d, 0x3c, 0xdb, 0x76,
        0x2d, 0x02, 0xd0, 0xbf, 0x37, 0xc9, 0xe5, 0x92
    };
    uint8_t hash256[32];
    ntru_sha256(test_string, len, (uint8_t*)&hash256);
    int valid256 = memcmp((uint8_t*)&hash256, (uint8_t*)&sha256, 32) == 0;

    /* test ntru_sha256_4way() */
    valid256 &= ntru_rand_init(&rand_ctx, &rng) == NTRU_SUCCESS;
    for (i=0; i<100; i++) {
        uint16_t inp_len = i;
        uint8_t test_a[inp_len];
        uint8_t test_b[inp_len];
        uint8_t test_c[inp_len];
        uint8_t test_d[inp_len];
        uint8_t *hash_inp[4];
        hash_inp[0] = test_a;
        hash_inp[1] = test_b;
        hash_inp[2] = test_c;
        hash_inp[3] = test_d;
        uint8_t j;
        for (j=0; j<4; j++)
            valid256 &= ntru_rand_generate(hash_inp[j], inp_len, &rand_ctx) == NTRU_SUCCESS;
        uint8_t H4_arr[4][32];
        uint8_t *H4[4];
        for (j=0; j<4; j++)
            H4[j] = H4_arr[j];
        ntru_sha256_4way(hash_inp, inp_len, H4);
        for (j=0; j<4; j++) {
            uint8_t H1[32];
            ntru_sha256(hash_inp[j], inp_len, H1);
            valid256 &= memcmp(H4[j], H1, 32) == 0;
        }
    }

    /* test ntru_sha256_8way() */
    valid256 &= ntru_rand_init(&rand_ctx, &rng) == NTRU_SUCCESS;
    for (i=0; i<100; i++) {
        uint16_t inp_len = i;
        uint8_t test_a[inp_len];
        uint8_t test_b[inp_len];
        uint8_t test_c[inp_len];
        uint8_t test_d[inp_len];
        uint8_t test_e[inp_len];
        uint8_t test_f[inp_len];
        uint8_t test_g[inp_len];
        uint8_t test_h[inp_len];
        uint8_t *hash_inp[8];
        hash_inp[0] = test_a;
        hash_inp[1] = test_b;
        hash_inp[2] = test_c;
        hash_inp[3] = test_d;
        hash_inp[4] = test_e;
        hash_inp[5] = test_f;
        hash_inp[6] = test_g;
        hash_inp[7] = test_h;
        uint8_t j;
        for (j=0; j<8; j++)
            valid256 &= ntru_rand_generate(hash_inp[j], inp_len, &rand_ctx) == NTRU_SUCCESS;
        uint8_t H8_arr[8][32];
        uint8_t *H8[8];
        for (j=0; j<8; j++)
            H8[j] = H8_arr[j];
        ntru_sha256_8way(hash_inp, inp_len, H8);
        for (j=0; j<8; j++) {
            uint8_t H1[32];
            ntru_sha256(hash_inp[j], inp_len, H1);
            valid256 &= memcmp(H8[j], H1, 32) == 0;
        }
    }

    valid256 &= ntru_rand_release(&rand_ctx) == NTRU_SUCCESS;

    uint8_t valid = valid1 && valid256;
    print_result("test_hash", valid);
    return valid;
}
