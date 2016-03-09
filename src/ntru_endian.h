#ifndef NTRU_ENDIAN_H
#define NTRU_ENDIAN_H

#ifdef __APPLE__
#include <libkern/OSByteOrder.h>
#define htole64(x) OSSwapHostToLittleInt64(x)
#define htole32(x) OSSwapHostToLittleInt32(x)
#define htole16(x) OSSwapHostToLittleInt16(x)
#endif
#ifdef __MINGW32__
/* assume little endian */
#define htole64(x) (x)
#define htole32(x) (x)
#define htole16(x) (x)
#endif
#ifdef __FreeBSD__
#include <sys/endian.h>
#endif

#ifdef __GLIBC__
#if __GLIBC__ <= 2 || ( __GLIBC__ == 2 && __GLIBC_MINOR__ < 9 )
#ifndef __powerpc__
/* assume little endian */
#define htole64(x) (x)
#define htole32(x) (x)
#define htole16(x) (x)
#endif
#endif
#endif

#ifdef __OS2__
#include <endian.h>
#endif

#endif   /* NTRU_ENDIAN_H */
