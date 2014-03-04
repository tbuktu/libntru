# C implementation of NTRUEncrypt

An implementation of the public-key encryption scheme NTRUEncrypt in C.

NTRU's main strengths are high performance and resistance to quantum computer
attacks. Its main drawback is that it is patent encumbered. The patents expire
in 2020; it is possible to modify this implementation so it becomes patent-free
in 2017.
For more information on the NTRUEncrypt algorithm, see the NTRU introduction
page:

  http://tbuktu.github.com/ntru/


## Compiling

Run ```make``` to build the library, or ```make test``` to run unit tests.

## Usage

    #include "ntru.h"

    /* key generation */
    struct NtruEncParams params = APR2011_439_FAST; /*see encparams.h for more*/
    NtruEncKeyPair kp;
    if (ntru_gen_key_pair(&params, &kp, ntru_rand_default) != 0)
        printf("keygen fail\n");

    /* deterministic key generation from password */
    char seed[17];
    strcpy(seed, "my test password");
    if (ntru_gen_key_pair_det(&params, &kp, ntru_rand_igf2, seed, strlen(seed)) != 0)
        printf("keygen fail\n");

    /* encryption */
    char msg[9];
    strcpy(msg, "whatever");
    char enc[ntru_enc_len(params.N, params.q)];
    if (ntru_encrypt(msg, strlen(msg), &kp.pub, &params, ntru_rand_default, enc) != 0)
        printf("encrypt fail\n");

    /* decryption */
    char dec[ntru_max_msg_len(&params)];
    int dec_len;
    if (ntru_decrypt((char*)&enc, &kp, &params, (unsigned char*)&dec, &dec_len) != 0)
        printf("decrypt fail\n");

    /* export key to char array */
    char pub_arr[ntru_enc_len(params.N, params.q)];
    ntru_export_pub(&kp.pub, pub_arr);

    /* import key from char array */
    NtruEncPubKey pub;
    ntru_import_pub(pub_arr, &pub);


## Supported Platforms
  libntru has been tested on Linux, Mac OS X and Windows (MingW).

## Further reading

  * Wikipedia article: http://en.wikipedia.org/wiki/NTRUEncrypt
  * Original NTRUEncrypt paper: http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.25.8422&rep=rep1&type=pdf
  * Follow-up NTRUEncrypt paper: http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.64.6834&rep=rep1&type=pdf
  * NTRU articles (technical and mathematical): http://www.securityinnovation.com/security-lab/crypto.html
  * EESS: http://grouper.ieee.org/groups/1363/lattPK/submissions/EESS1v2.pdf
  * Jeffrey Hoffstein et al: An Introduction to Mathematical Cryptography, Springer-Verlag, ISBN 978-0-387-77993-5
