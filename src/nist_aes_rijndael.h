/*
 * Copyright (c) 2007 Henric Jungheim <software@henric.info>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * Interface adapter for Rijndael implementation (for use by NIST SP 800-90 CTR_DRBG)
 */

#ifndef NIST_AES_RIJNDAEL_H
#define NIST_AES_RIJNDAEL_H

#ifndef __RIJNDAEL_H
#include "rijndael.h"
#endif

#define NIST_AES_MAXKEYBITS		256
#define NIST_AES_MAXKEYBYTES	(NIST_AES_MAXKEYBITS / 8)
#define NIST_AES_MAXKEYINTS	(NIST_AES_MAXKEYBYTES / sizeof(int))

#define NIST_AES_BLOCKSIZEBITS	128
#define NIST_AES_BLOCKSIZEBYTES	(NIST_AES_BLOCKSIZEBITS / 8)
#define NIST_AES_BLOCKSIZEINTS	(NIST_AES_BLOCKSIZEBYTES / sizeof(int))

typedef struct {
	int Nr;			/* key-length-dependent number of rounds */
	unsigned int ek[4*(AES_MAXROUNDS + 1)];	/* encrypt key schedule */
} NIST_AES_ENCRYPT_CTX;

static __inline void
NIST_AES_ECB_Encrypt(const NIST_AES_ENCRYPT_CTX* ctx, const void* src, void* dst)
{
	rijndaelEncrypt(ctx->ek, ctx->Nr, (const unsigned char *)src, (unsigned char *)dst);
}

static __inline int
NIST_AES_Schedule_Encryption(NIST_AES_ENCRYPT_CTX* ctx, const void* key, int bits)
{
	ctx->Nr = rijndaelKeySetupEnc(ctx->ek, (const unsigned char *)key, bits);
	if (!ctx->Nr)
		return 1;

	return 0;
}

#endif /* NIST_AES_RIJNDAEL_H */
