#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include "ntru.h"
#include "rand.h"

#define NUM_ITER_KEYGEN 50
#define NUM_ITER_ENCDEC 10000

/*
 * The __MACH__ and __MINGW32__ code below is from
 * https://github.com/credentials/silvia/commit/e327067cf7feaf62ac0bde84d13ee47372c0094e
 */

#ifdef __MACH__

/*
 * Mac OS X does not have clock_gettime for some reason
 *
 * Use solution from here to fix it:
 * http://stackoverflow.com/questions/5167269/clock-gettime-alternative-in-mac-os-x
 */

#define CLOCK_REALTIME 0

#include <mach/clock.h>
#include <mach/mach.h>

void clock_gettime(uint32_t clock, struct timespec* the_time)
{
clock_serv_t cclock;
mach_timespec_t mts;

host_get_clock_service(mach_host_self(), CALENDAR_CLOCK, &cclock);
clock_get_time(cclock, &mts);
mach_port_deallocate(mach_task_self(), cclock);

the_time->tv_sec = mts.tv_sec;
the_time->tv_nsec = mts.tv_nsec;
}

#endif // __MACH__

#ifdef __MINGW32__

/*
 * MinGW does not have clock_gettime for some reason
 *
 * Use solution from here to fix it:
 * http://stackoverflow.com/questions/5404277/porting-clock-gettime-to-windows
 */

#include <stdarg.h>
#include <windef.h>
#include <winnt.h>
#include <winbase.h>

#define CLOCK_REALTIME 0

/* POSIX.1b structure for a time value. This is like a `struct timeval' but
has nanoseconds instead of microseconds. */
struct timespec {
  uint32_t tv_sec;    /* Seconds. */
  uint32_t tv_nsec;   /* Nanoseconds. */
};

LARGE_INTEGER getFILETIMEoffset()
{
    SYSTEMTIME s;
    FILETIME f;
    LARGE_INTEGER t;

    s.wYear = 1970;
    s.wMonth = 1;
    s.wDay = 1;
    s.wHour = 0;
    s.wMinute = 0;
    s.wSecond = 0;
    s.wMilliseconds = 0;
    SystemTimeToFileTime(&s, &f);
    t.QuadPart = f.dwHighDateTime;
    t.QuadPart <<= 32;
    t.QuadPart |= f.dwLowDateTime;
    return (t);
}

void clock_gettime(uint32_t X, struct timespec *ts)
{
    LARGE_INTEGER t;
    FILETIME f;
    double nanoseconds;
    static LARGE_INTEGER offset;
    static double frequencyToNanoseconds;
    static uint32_t initialized = 0;
    static BOOL usePerformanceCounter = 0;

    if (!initialized) {
        LARGE_INTEGER performanceFrequency;
        initialized = 1;
        usePerformanceCounter = QueryPerformanceFrequency(&performanceFrequency);
        if (usePerformanceCounter) {
            QueryPerformanceCounter(&offset);
            frequencyToNanoseconds = (double)performanceFrequency.QuadPart / 1000000000.;
        } else {
            offset = getFILETIMEoffset();
            frequencyToNanoseconds = 0.010;
        }
    }
    if (usePerformanceCounter) QueryPerformanceCounter(&t);
    else {
        GetSystemTimeAsFileTime(&f);
        t.QuadPart = f.dwHighDateTime;
        t.QuadPart <<= 32;
        t.QuadPart |= f.dwLowDateTime;
    }

    t.QuadPart -= offset.QuadPart;
    nanoseconds = (double)t.QuadPart / frequencyToNanoseconds;
    t.QuadPart = nanoseconds;
    ts->tv_sec = t.QuadPart / 1000000000;
    ts->tv_nsec = t.QuadPart % 1000000000;
}

#endif // __MINGW32__

int main(int argc, char **argv) {
    printf("Please wait...\n");

    NtruEncKeyPair kp;

#ifndef NTRU_AVOID_HAMMING_WT_PATENT
    NtruEncParams params = EES439EP1;
#else
    NtruEncParams params = EES761EP1;
#endif
    uint8_t success = 1;
    uint32_t i;
    struct timespec t1;
    clock_gettime(CLOCK_REALTIME, &t1);
    NtruRandGen rng = NTRU_RNG_DEFAULT;
    NtruRandContext rand_ctx;
    ntru_rand_init(&rand_ctx, &rng);
    for (i=0; i<NUM_ITER_KEYGEN; i++)
        success &= ntru_gen_key_pair(&params, &kp, &rand_ctx) == 0;
    struct timespec t2;
    clock_gettime(CLOCK_REALTIME, &t2);
    double time = (1000000000.0*(t2.tv_sec-t1.tv_sec)+t2.tv_nsec-t1.tv_nsec) / NUM_ITER_KEYGEN;
    double per_sec = 1000000000.0 / time;
    printf("%f key generations/sec\n", per_sec);

    uint16_t enc_len = ntru_enc_len(&params);
    char plain_char[33];
    strcpy(plain_char, "test message secret test message");
    uint8_t plain[strlen(plain_char)];
    for (i=0; i<strlen(plain_char); i++)
        plain[i] = plain_char[i];
    uint8_t encrypted[enc_len];
    uint8_t decrypted[strlen(plain_char)];
    clock_gettime(CLOCK_REALTIME, &t1);
    for (i=0; i<NUM_ITER_ENCDEC; i++)
        success &= ntru_encrypt((uint8_t*)&plain, strlen(plain_char), &kp.pub, &params, &rand_ctx, (uint8_t*)&encrypted) == 0;
    clock_gettime(CLOCK_REALTIME, &t2);
    time = (1000000000.0*(t2.tv_sec-t1.tv_sec)+t2.tv_nsec-t1.tv_nsec) / NUM_ITER_ENCDEC;
    per_sec = 1000000000.0 / time;
    printf("%f encryptions/sec\n", per_sec);
    ntru_rand_release(&rand_ctx);

    uint16_t dec_len;
    clock_gettime(CLOCK_REALTIME, &t1);
    for (i=0; i<NUM_ITER_ENCDEC; i++)
        success &= ntru_decrypt((uint8_t*)&encrypted, &kp, &params, (uint8_t*)&decrypted, &dec_len) == 0;
    clock_gettime(CLOCK_REALTIME, &t2);
    time = (1000000000.0*(t2.tv_sec-t1.tv_sec)+t2.tv_nsec-t1.tv_nsec) / NUM_ITER_ENCDEC;
    per_sec = 1000000000.0 / time;
    printf("%f decryptions/sec\n", per_sec);

    if (!success)
        printf("Error!\n");
    return success ? 0 : 1;
}
