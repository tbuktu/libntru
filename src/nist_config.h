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
 * NIST SP 800-90 Configuration (Random Number Generator)
 */

#ifndef NIST_CONFIG_H
#define NIST_CONFIG_H

/* #define NIST_IS_LITTLE_ENDIAN 1 */
#ifdef WIN32
#include <Winsock2.h>
#else
#include <netinet/in.h>
#endif
#define NIST_HTONL(x) htonl(x)

/* #define NIST_ZEROIZE 1 */

#if 0
/* Use the VIA padlock hardware as the AES implementation */
#ifndef NIST_AES_PADLOCK_H_
#include "nist_aes_padlock.h"
#endif
#else
#ifndef NIST_AES_RIJNDAEL_H_
#include "nist_aes_rijndael.h"
#endif
#endif

/* Use AES-256 as the block cipher */
#ifndef NIST_CTR_DRBG_AES256_H
#include "nist_ctr_drbg_aes256.h"
#endif

#endif /* NIST_CONFIG_H */
