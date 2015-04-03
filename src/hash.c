#include <string.h>
#include <stdint.h>
#if defined __SSSE3__ && _LP64
#include <tmmintrin.h>
#endif
#ifdef WIN32
#include <Winsock2.h>
#else
#include <netinet/in.h>
#endif
#include "sph_sha1.h"
#include "sph_sha2.h"
#include "hash.h"

#if defined __SSSE3__ && _LP64
typedef struct {
    uint32_t A[8], B[8], C[8], D[8], E[8];
    uint32_t Nl,Nh;
    uint32_t data[4][16];
    uint8_t num;   /* 1 or 2 */
} SHA1_MB_CTX;
typedef struct {
    uint32_t A[8];
    uint32_t B[8];
    uint32_t C[8];
    uint32_t D[8];
    uint32_t E[8];
    uint32_t F[8];
    uint32_t G[8];
    uint32_t H[8];
    uint32_t Nl, Nh;
    uint8_t num;   /* 1 or 2 */
    uint32_t data[4][16];
} SHA256_MB_CTX;
typedef struct {
    uint8_t *ptr;
    uint32_t blocks;
} HASH_DESC;
#endif   /* __SSSE3__ && _LP64 */

void ntru_sha1(uint8_t *input, uint16_t input_len, uint8_t *digest) {
    sph_sha1_context context;
    sph_sha1_init(&context);
    sph_sha1(&context, input, input_len);
    sph_sha1_close(&context, digest);
}

#if defined __SSSE3__ && _LP64
uint64_t OPENSSL_ia32cap_P = 0;   /* don’t detect SHA extensions for now */

extern void sha1_multi_block(SHA1_MB_CTX *, HASH_DESC *, int num);

extern void sha256_multi_block(SHA256_MB_CTX *, HASH_DESC *, int num);

void SHA1_MB_Init(SHA1_MB_CTX *ctx) {
    memset(ctx, 0, sizeof(*ctx));
    __m128i a = _mm_set1_epi32(0x67452301);
    __m128i b = _mm_set1_epi32(0xefcdab89);
    __m128i c = _mm_set1_epi32(0x98badcfe);
    __m128i d = _mm_set1_epi32(0x10325476);
    __m128i e = _mm_set1_epi32(0xc3d2e1f0);
    _mm_storeu_si128((__m128i*)&ctx->A, a);
    _mm_storeu_si128((__m128i*)&ctx->B, b);
    _mm_storeu_si128((__m128i*)&ctx->C, c);
    _mm_storeu_si128((__m128i*)&ctx->D, d);
    _mm_storeu_si128((__m128i*)&ctx->E, e);
}

void SHA1_MB_Update(SHA1_MB_CTX *ctx, uint8_t *data[4], size_t len) {
    if (len == 0)
        return;

    uint32_t l = (ctx->Nl + (((uint32_t) len) << 3)) & 0xffffffffUL;
    /*
     * 95-05-24 eay Fixed a bug with the overflow handling, thanks to Wei Dai
     * <weidai@eskimo.com> for pointing it out.
     */
    if (l < ctx->Nl)              /* overflow */
        ctx->Nh++;
    ctx->Nh += (uint32_t) (len >> 29); /* might cause compiler warning on
                                       * 16-bit */
    ctx->Nl = l;

    uint8_t *data_[4];
    uint8_t i;
    for (i=0; i<4; i++)
        data_[i] = data[i];

    size_t n = len / 64;
    if (n > 0) {
        HASH_DESC hdesc[4];
        for (i=0; i<4; i++) {
            hdesc[i].ptr = data[i];
            hdesc[i].blocks = n;
        }
        sha1_multi_block(ctx, hdesc, 1);
        n *= 64;
        for (i=0; i<4; i++)
            data_[i] += n;
        len -= n;
    }

    if (len != 0) {
        ctx->num = (uint32_t)len;
        for (i=0; i<4; i++) {
            uint8_t *d = (uint8_t*)ctx->data[i];
            memcpy(d, data_[i], len);
        }
    }
}

void SHA1_MB_Final(uint8_t *digest[4], SHA1_MB_CTX *ctx) {
    size_t n = ctx->num;
    uint8_t i;
    for (i=0; i<4; i++) {
        uint8_t *d = (uint8_t*)ctx->data[i];
        *(d+n) = 0x80;
    }
    n++;
    for (i=0; i<4; i++)
        memset(((uint8_t*)ctx->data[i]) + n, 0, 64 - n);

    if (n > (64 - 8)) {
        n = 0;
        HASH_DESC hdesc[4];
        for (i=0; i<4; i++) {
            hdesc[i].ptr = (uint8_t*)ctx->data[i];
            hdesc[i].blocks = 1;
        }
        sha1_multi_block(ctx, hdesc, 1);
    }
    for (i=0; i<4; i++) {
        uint8_t *d = (uint8_t*)&ctx->data[i];
        memset(d+n, 0, 64-8-n);

        d += 64 - 8;
        uint32_t *d32 = (uint32_t*)d;
        *d32 = ntohl(ctx->Nh);

        d += 4;
        d32 = (uint32_t*)d;
        *d32 = ntohl(ctx->Nl);
    }
    HASH_DESC hdesc[4];
    for (i=0; i<4; i++) {
        hdesc[i].ptr = (uint8_t*)ctx->data[i];
        hdesc[i].blocks = 1;
    }
    sha1_multi_block(ctx, hdesc, 1);

    for (i=0; i<4; i++) {
        uint32_t *d32 = (uint32_t*)digest[i];
        *(d32++) = ntohl(ctx->A[i]);
        *(d32++) = ntohl(ctx->B[i]);
        *(d32++) = ntohl(ctx->C[i]);
        *(d32++) = ntohl(ctx->D[i]);
        *d32 = ntohl(ctx->E[i]);
    }
}
#endif   /* __SSSE3__ && _LP64 */

void ntru_sha1_4way(uint8_t *input[4], uint16_t input_len, uint8_t *digest[4]) {
#if defined __SSSE3__ && _LP64
    SHA1_MB_CTX ctx;
    SHA1_MB_Init(&ctx);
    SHA1_MB_Update(&ctx, input, input_len);
    SHA1_MB_Final(digest, &ctx);
#else
    uint8_t i;
    for (i=0; i<4; i++)
        ntru_sha1(input[i], input_len, digest[i]);
#endif   /* __SSSE3__ && _LP64 */
}

void ntru_sha256(uint8_t *input, uint16_t input_len, uint8_t *digest) {
    sph_sha256_context context;
    sph_sha256_init(&context);
    sph_sha256(&context, input, input_len);
    sph_sha256_close(&context, digest);
}

#if defined __SSSE3__ && _LP64
void SHA256_MB_Init(SHA256_MB_CTX *ctx) {
    memset(ctx, 0, sizeof(*ctx));
    __m128i a = _mm_set1_epi32(0x6a09e667);
    __m128i b = _mm_set1_epi32(0xbb67ae85);
    __m128i c = _mm_set1_epi32(0x3c6ef372);
    __m128i d = _mm_set1_epi32(0xa54ff53a);
    __m128i e = _mm_set1_epi32(0x510e527f);
    __m128i f = _mm_set1_epi32(0x9b05688c);
    __m128i g = _mm_set1_epi32(0x1f83d9ab);
    __m128i h = _mm_set1_epi32(0x5be0cd19);
    _mm_storeu_si128((__m128i*)&ctx->A, a);
    _mm_storeu_si128((__m128i*)&ctx->B, b);
    _mm_storeu_si128((__m128i*)&ctx->C, c);
    _mm_storeu_si128((__m128i*)&ctx->D, d);
    _mm_storeu_si128((__m128i*)&ctx->E, e);
    _mm_storeu_si128((__m128i*)&ctx->F, f);
    _mm_storeu_si128((__m128i*)&ctx->G, g);
    _mm_storeu_si128((__m128i*)&ctx->H, h);
}

void SHA256_MB_Update(SHA256_MB_CTX *ctx, uint8_t *data[4], size_t len) {
    if (len == 0)
        return;

    uint32_t l = (ctx->Nl + (((uint32_t) len) << 3)) & 0xffffffffUL;
    /*
     * 95-05-24 eay Fixed a bug with the overflow handling, thanks to Wei Dai
     * <weidai@eskimo.com> for pointing it out.
     */
    if (l < ctx->Nl)              /* overflow */
        ctx->Nh++;
    ctx->Nh += (uint32_t) (len >> 29); /* might cause compiler warning on
                                       * 16-bit */
    ctx->Nl = l;

    uint8_t *data_[4];
    uint8_t i;
    for (i=0; i<4; i++)
        data_[i] = data[i];

    size_t n = len / 64;
    if (n > 0) {
        HASH_DESC hdesc[4];
        for (i=0; i<4; i++) {
            hdesc[i].ptr = data[i];
            hdesc[i].blocks = n;
        }
        sha256_multi_block(ctx, hdesc, 1);
        n *= 64;
        for (i=0; i<4; i++)
            data_[i] += n;
        len -= n;
    }

    if (len != 0) {
        ctx->num = (uint32_t)len;
        for (i=0; i<4; i++) {
            uint8_t *d = (uint8_t*)ctx->data[i];
            memcpy(d, data_[i], len);
        }
    }
}

void SHA256_MB_Final(uint8_t *digest[4], SHA256_MB_CTX *ctx) {
    size_t n = ctx->num;
    uint8_t i;
    for (i=0; i<4; i++) {
        uint8_t *d = (uint8_t*)ctx->data[i];
        *(d+n) = 0x80;
    }
    n++;
    for (i=0; i<4; i++)
        memset(((uint8_t*)ctx->data[i]) + n, 0, 64 - n);

    if (n > (64 - 8)) {
        n = 0;
        HASH_DESC hdesc[4];
        for (i=0; i<4; i++) {
            hdesc[i].ptr = (uint8_t*)ctx->data[i];
            hdesc[i].blocks = 1;
        }
        sha256_multi_block(ctx, hdesc, 1);
    }
    for (i=0; i<4; i++) {
        uint8_t *d = (uint8_t*)&ctx->data[i];
        memset(d+n, 0, 64-8-n);

        d += 64 - 8;
        uint32_t *d32 = (uint32_t*)d;
        *d32 = ntohl(ctx->Nh);

        d += 4;
        d32 = (uint32_t*)d;
        *d32 = ntohl(ctx->Nl);
    }
    HASH_DESC hdesc[4];
    for (i=0; i<4; i++) {
        hdesc[i].ptr = (uint8_t*)ctx->data[i];
        hdesc[i].blocks = 1;
    }
    sha256_multi_block(ctx, hdesc, 1);

    for (i=0; i<4; i++) {
        uint32_t *d32 = (uint32_t*)digest[i];
        *(d32++) = ntohl(ctx->A[i]);
        *(d32++) = ntohl(ctx->B[i]);
        *(d32++) = ntohl(ctx->C[i]);
        *(d32++) = ntohl(ctx->D[i]);
        *(d32++) = ntohl(ctx->E[i]);
        *(d32++) = ntohl(ctx->F[i]);
        *(d32++) = ntohl(ctx->G[i]);
        *d32 = ntohl(ctx->H[i]);
    }
}
#endif   /* __SSSE3__ && _LP64 */

void ntru_sha256_4way(uint8_t *input[4], uint16_t input_len, uint8_t *digest[4]) {
#if defined __SSSE3__ && _LP64
    SHA256_MB_CTX ctx;
    SHA256_MB_Init(&ctx);
    SHA256_MB_Update(&ctx, input, input_len);
    SHA256_MB_Final(digest, &ctx);
#else
    uint8_t i;
    for (i=0; i<4; i++)
        ntru_sha256(input[i], input_len, digest[i]);
#endif
}
