# C implementation of NTRUEncrypt

An implementation of the public-key encryption scheme NTRUEncrypt in C.

NTRU's main strengths are high performance and resistance to quantum computer
attacks. Its main drawback is that it is patent encumbered. The patents expire
in 2020; when built with the NTRU_AVOID_HAMMING_WT_PATENT flag, libntru becomes
patent-free in 2017.

Benchmark results:

![Benchmark results](https://tbuktu.github.io/ntru/images/bench.png?raw=true "Benchmark results")

For more information on the NTRUEncrypt algorithm, see the NTRU introduction
page at https://tbuktu.github.com/ntru/.


## Compiling

Run ```make``` to build the library, or ```make test``` to run unit tests. ```make bench``` builds a benchmark program.

The ```SSE``` environment variable enables SSSE3 support (```SSE=yes```)
or disables it (```SSE=no```).
Default on Linux and MacOS is to autodetect SSSE3 on the build host,
Windows default is no SSSE3.

## Usage

    #include "ntru.h"

    /* key generation */
    struct NtruEncParams params = EES449EP1; /*see encparams.h for more*/
    NtruRandGen rng_def = NTRU_RNG_DEFAULT;
    NtruRandContext rand_ctx_def;
    ntru_rand_init(&rand_ctx_def, &rng_def);
    NtruEncKeyPair kp;
    if (ntru_gen_key_pair(&params, &kp, &rand_ctx_def) != NTRU_SUCCESS)
        printf("keygen fail\n");

    /* deterministic key generation from password */
    uint8_t seed[17];
    strcpy(seed, "my test password");
    NtruRandGen rng_igf2 = NTRU_RNG_IGF2;
    NtruRandContext rand_ctx_igf2;
    ntru_rand_init_det(&rand_ctx_igf2, &rng_igf2, seed, strlen(seed));
    if (ntru_gen_key_pair(&params, &kp, &rand_ctx_igf2) != NTRU_SUCCESS)
        printf("keygen fail\n");

    /* encryption */
    uint8_t msg[9];
    strcpy(msg, "whatever");
    uint8_t enc[ntru_enc_len(&params)];
    if (ntru_encrypt(msg, strlen(msg), &kp.pub, &params, &rand_ctx_def, enc) != NTRU_SUCCESS)
        printf("encrypt fail\n");

    /* release RNG resources */
    ntru_rand_release(&rand_ctx_def);
    ntru_rand_release(&rand_ctx_igf2);

    /* decryption */
    uint8_t dec[ntru_max_msg_len(&params)];
    uint16_t dec_len;
    if (ntru_decrypt((uint8_t*)&enc, &kp, &params, (uint8_t*)&dec, &dec_len) != NTRU_SUCCESS)
        printf("decrypt fail\n");

    /* export key to uint8_t array */
    uint8_t pub_arr[ntru_pub_len(&params)];
    ntru_export_pub(&kp.pub, pub_arr);

    /* import key from uint8_t array */
    NtruEncPubKey pub;
    ntru_import_pub(pub_arr, &pub);

For encryption of messages longer than `ntru_max_msg_len(...)`, see `src/hybrid.c`
(requires OpenSSL lib+headers, use `make hybrid` to build).

## Supported Platforms
  libntru has been tested on Linux, Mac OS X and Windows (MingW).

## Further reading

  * Wikipedia article: https://en.wikipedia.org/wiki/NTRUEncrypt
  * Original NTRUEncrypt paper: https://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.25.8422&rep=rep1&type=pdf
  * Follow-up NTRUEncrypt paper: https://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.64.6834&rep=rep1&type=pdf
  * NTRU articles (technical and mathematical): https://www.securityinnovation.com/products/encryption-libraries/ntru-crypto/ntru-resources.html
  * EESS: http://grouper.ieee.org/groups/1363/lattPK/submissions/EESS1v2.pdf
  * Jeffrey Hoffstein et al: An Introduction to Mathematical Cryptography, Springer-Verlag, ISBN 978-0-387-77993-5
