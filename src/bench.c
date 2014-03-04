#include <stdio.h>
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

void clock_gettime(int clock, struct timespec* the_time)
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
  long int tv_sec;	/* Seconds. */
  long int tv_nsec;	/* Nanoseconds. */
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

void clock_gettime(int X, struct timespec *ts)
{
    LARGE_INTEGER t;
    FILETIME f;
    double nanoseconds;
    static LARGE_INTEGER offset;
    static double frequencyToNanoseconds;
    static int initialized = 0;
    static BOOL usePerformanceCounter = 0;

    if (!initialized) {
        LARGE_INTEGER performanceFrequency;
        initialized = 1;
        usePerformanceCounter = QueryPerformanceFrequency(&performanceFrequency);
        if (usePerformanceCounter) {
            QueryPerformanceCounter(&offset);
            frequencyToNanoseconds = (double)performanceFrequency.QuadPart / 1000.;
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

    NtruEncParams params = APR2011_439_FAST;
    int success = 1;
    int i;
    struct timespec t1;
    clock_gettime(CLOCK_REALTIME, &t1);
    for (i=0; i<NUM_ITER_KEYGEN; i++)
        success &= ntru_gen_key_pair(&params, &kp, ntru_rand_default) == 0;
    struct timespec t2;
    clock_gettime(CLOCK_REALTIME, &t2);
    double time = (1000000000.0*(t2.tv_sec-t1.tv_sec)+t2.tv_nsec-t1.tv_nsec) / NUM_ITER_KEYGEN;
    double per_sec = 1000000000.0 / time;
    printf("%f key generations/sec\n", per_sec);

    int enc_len = ntru_enc_len(params.N, params.q);
    char plain[33];
    strcpy(plain, "test message secret test message");
    char encrypted[enc_len];
    char decrypted[strlen(plain)];
    clock_gettime(CLOCK_REALTIME, &t1);
    for (i=0; i<NUM_ITER_ENCDEC; i++)
        success &= ntru_encrypt((char*)&plain, strlen(plain), &kp.pub, &params, ntru_rand_default, (char*)&encrypted) == 0;
    clock_gettime(CLOCK_REALTIME, &t2);
    time = (1000000000.0*(t2.tv_sec-t1.tv_sec)+t2.tv_nsec-t1.tv_nsec) / NUM_ITER_ENCDEC;
    per_sec = 1000000000.0 / time;
    printf("%f encryptions/sec\n", per_sec);

    int dec_len;
    clock_gettime(CLOCK_REALTIME, &t1);
    for (i=0; i<NUM_ITER_ENCDEC; i++)
        success &= ntru_decrypt((char*)&encrypted, &kp, &params, (unsigned char*)&decrypted, &dec_len) == 0;
    clock_gettime(CLOCK_REALTIME, &t2);
    time = (1000000000.0*(t2.tv_sec-t1.tv_sec)+t2.tv_nsec-t1.tv_nsec) / NUM_ITER_ENCDEC;
    per_sec = 1000000000.0 / time;
    printf("%f decryptions/sec\n", per_sec);

    if (!success)
        printf("Error!\n");
    return success ? 0 : 1;
}
