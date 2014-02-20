#include <unistd.h>
#include <fcntl.h>
#include "err.h"
#ifdef WIN32
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <Wincrypt.h>
#endif

#ifdef WIN32
int ntru_rand_wincrypt(unsigned rand_data[], int len) {
    static HCRYPTPROV hCryptProv = NULL;
    if (hCryptProv == NULL) {
        int result = CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, 0);
        if (!result) {
            if (GetLastError() == NTE_BAD_KEYSET)   // see http://support.microsoft.com/kb/238187
                result = CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_NEWKEYSET);
            if (!result)
                return NTRU_ERR_PRNG;
        }
    }
    return CryptGenRandom(hCryptProv, len * sizeof *rand_data, rand_data);
}

int ntru_rand_default(unsigned rand_data[], int len) {
    return ntru_rand_wincrypt(rand_data, len);
}

#else

int ntru_rand_devrandom(unsigned rand_data[], int len) {
    int rand_fd = open("/dev/random", O_RDONLY);
    if (rand_fd < 0)
        return 0;
    int tot_bytes = 0;
    unsigned len_bytes = len * (sizeof rand_data[0]);
    while (tot_bytes < len_bytes) {
        int bytes_read = read(rand_fd, ((char*)rand_data)+tot_bytes, len_bytes-tot_bytes);
        if (bytes_read <= 0)
            return 0;
        tot_bytes += bytes_read;
    }
    close(rand_fd);
    return tot_bytes == len_bytes;
}

int ntru_rand_devurandom(unsigned rand_data[], int len) {
    int rand_fd = open("/dev/urandom", O_RDONLY);
    if (rand_fd < 0)
        return 0;
    int bytes_read = read(rand_fd, rand_data, len * sizeof *rand_data);
    close(rand_fd);
    return bytes_read == len * sizeof rand_data[0];
}

int ntru_rand_default(unsigned rand_data[], int len) {
    return ntru_rand_devurandom(rand_data, len);
}
#endif // WIN32
