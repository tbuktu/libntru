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
 * NIST SP 800-90 CTR_DRBG (Random Number Generator)
 */

#ifndef NIST_CTR_DRBG_H
#define NIST_CTR_DRBG_H

#ifndef NIST_CONFIG_H
#include "nist_config.h"
#endif

#define NIST_BLOCK_SEEDLEN			(NIST_BLOCK_KEYLEN + NIST_BLOCK_OUTLEN)
#define NIST_BLOCK_SEEDLEN_BYTES	(NIST_BLOCK_SEEDLEN / 8)
#define NIST_BLOCK_SEEDLEN_INTS		(NIST_BLOCK_SEEDLEN_BYTES / sizeof(int))

#ifndef NIST_KEY_ALIGNMENT
#define NIST_KEY_ALIGNMENT
#endif

typedef struct {
	unsigned int reseed_counter;
	NIST_Key ctx;
	unsigned int V[NIST_BLOCK_OUTLEN_INTS];
} NIST_KEY_ALIGNMENT NIST_CTR_DRBG;


int
nist_ctr_initialize(void);

int 
nist_ctr_drbg_generate(NIST_CTR_DRBG* drbg,
	void* output_string, int output_string_length,
	const void* additional_input, int additional_input_length);

int
nist_ctr_drbg_reseed(NIST_CTR_DRBG* drbg,
	const void* entropy_input, int entropy_input_length,
	const void* additional_input, int additional_input_length);

int
nist_ctr_drbg_instantiate(NIST_CTR_DRBG* drbg,
	const void* entropy_input, int entropy_input_length,
	const void* nonce, int nonce_length,
	const void* personalization_string, int personalization_string_length);

int
nist_ctr_drbg_destroy(NIST_CTR_DRBG* );

void
nist_dump_simple_hex(const void* data, int length);

void
nist_dump_hex(const void* data, int length);

void
nist_dump_named_hex(const char* name, const void* data, int length);

void
nist_dump_ctr_drbg(const NIST_CTR_DRBG* drbg);

void
nist_dump_block_ctx(const NIST_Key* ctx);


#ifdef NIST_ZEROIZE
#define nist_zeroize(p, s) memset(p, 0, s)
#else
#define nist_zeroize(p, s) do { } while(0)
#endif

/*
 * The test vectors will indicate failure if the 
 * byte ordering is set incorrectly.
 * Pretending to be little endian will improve performance
 * slightly but should not have an impact on
 * security (a byte-swapped nonce is still a nonce).
 */

#ifndef NIST_HTONL
#if defined(NIST_IS_LITTLE_ENDIAN)
#define NIST_HTONL(x) nist_htonl(x)
static __inline unsigned int nist_htonl(unsigned int x)
{
	return 
		((((x) & 0xff000000) >> 24) |
		 (((x) & 0x00ff0000) >>  8) |
		 (((x) & 0x0000ff00) <<  8) |
		 (((x) & 0x000000ff) << 24));
}
#elif defined(NIST_IS_BIG_ENDIAN)
#define NIST_HTONL(x) (x)
#else
#error "Define NIST_HTONL or define NIST_IS_{BIG|LITTLE}_ENDIAN."
#endif
#endif /* NIST_HTONL */

#ifndef NIST_NTOHL
/* BE->H and H->BE are usually the same. */
#define NIST_NTOHL(x) NIST_HTONL(x)
#endif /* NIST_NTOHL */

#endif /* NIST_CTR_DRBG_H */

