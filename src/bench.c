#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "ntru.h"

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

#endif /* __MACH__ */

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

#endif /* __MINGW32__ */

int compare_double(const void *p1, const void *p2) {
    double t1 = *(double*)p1;
    double t2 = *(double*)p2;
    return t1<t2 ? -1 : (t1>t2 ? 1 : 0);
}

double median(double *samples, int num_samples) {
    if (num_samples == 0)
        return 0;
    if (num_samples == 1)
        return samples[0];
    qsort(samples, num_samples, sizeof(samples[0]), compare_double);
    if (num_samples%2 == 0)
        return (samples[num_samples/2-1]+samples[num_samples/2]) / 2;
    else
        return samples[num_samples/2];
}

void print_time(char *label, double *samples, int num_samples) {
    double time = median(samples, num_samples);
    double per_sec = 1000000.0 / time;
#ifdef WIN32
    printf("%s %dus=%d/sec   ", label, (uint32_t)time, (uint32_t)per_sec);
#else
    printf("%s %dμs=%d/sec   ", label, (uint32_t)time, (uint32_t)per_sec);
#endif
    fflush(stdout);
}

int main(int argc, char **argv) {
    printf("Please wait...\n");

    NtruEncParams param_arr[] = ALL_PARAM_SETS;
    uint8_t success = 1;

    uint8_t param_idx;
    for (param_idx=0; param_idx<sizeof(param_arr)/sizeof(param_arr[0]); param_idx++) {
        NtruEncParams params = param_arr[param_idx];
        NtruEncKeyPair kp;
        uint32_t i;
        struct timespec t1, t2;
        printf("%-10s   ", params.name);
        fflush(stdout);

        double samples_keygen[NUM_ITER_KEYGEN];
        NtruRandGen rng = NTRU_RNG_DEFAULT;
        NtruRandContext rand_ctx;
        success &= ntru_rand_init(&rand_ctx, &rng) == NTRU_SUCCESS;
        for (i=0; i<NUM_ITER_KEYGEN; i++) {
            clock_gettime(CLOCK_REALTIME, &t1);
            success &= ntru_gen_key_pair(&params, &kp, &rand_ctx) == NTRU_SUCCESS;
            clock_gettime(CLOCK_REALTIME, &t2);
            double duration = 1000000000.0*(t2.tv_sec-t1.tv_sec) + t2.tv_nsec-t1.tv_nsec;   /* nanoseconds */
            samples_keygen[i] = duration / 1000.0;   /* microseconds */
        }
        print_time("keygen", samples_keygen, NUM_ITER_KEYGEN);

        double samples_encdec[NUM_ITER_ENCDEC];
        uint16_t max_len = ntru_max_msg_len(&params);   /* max message length for this param set */
        uint8_t plain[max_len];
        success &= ntru_rand_generate(plain, max_len, &rand_ctx) == NTRU_SUCCESS;
        uint16_t enc_len = ntru_enc_len(&params);
        uint8_t encrypted[enc_len];
        uint8_t decrypted[max_len];
        for (i=0; i<NUM_ITER_ENCDEC; i++) {
            clock_gettime(CLOCK_REALTIME, &t1);
            success &= ntru_encrypt((uint8_t*)&plain, max_len, &kp.pub, &params, &rand_ctx, (uint8_t*)&encrypted) == NTRU_SUCCESS;
            clock_gettime(CLOCK_REALTIME, &t2);
            double duration = 1000000000.0*(t2.tv_sec-t1.tv_sec) + t2.tv_nsec-t1.tv_nsec;   /* nanoseconds */
            samples_encdec[i] = duration / 1000.0;   /* microseconds */
        }
        print_time("enc", samples_encdec, NUM_ITER_ENCDEC);
        success &= ntru_rand_release(&rand_ctx) == NTRU_SUCCESS;

        uint16_t dec_len;
        for (i=0; i<NUM_ITER_ENCDEC; i++) {
            clock_gettime(CLOCK_REALTIME, &t1);
            success &= ntru_decrypt((uint8_t*)&encrypted, &kp, &params, (uint8_t*)&decrypted, &dec_len) == NTRU_SUCCESS;
            clock_gettime(CLOCK_REALTIME, &t2);
            double duration = 1000000000.0*(t2.tv_sec-t1.tv_sec) + t2.tv_nsec-t1.tv_nsec;   /* nanoseconds */
            samples_encdec[i] = duration / 1000.0;   /* microseconds */
        }
        print_time("dec", samples_encdec, NUM_ITER_ENCDEC);
        printf("\n");
    }

    if (!success)
        printf("Error!\n");
    return success ? 0 : 1;
}
