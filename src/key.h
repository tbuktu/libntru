#ifndef NTRU_KEY_H
#define NTRU_KEY_H

#include "types.h"
#include "encparams.h"

void ntru_export_pub(NtruEncPubKey *key, uint8_t *arr);

uint16_t ntru_import_pub(uint8_t *arr, NtruEncPubKey *key);

uint16_t ntru_export_priv(NtruEncPrivKey *key, uint8_t *arr);

void ntru_import_priv(uint8_t *arr, NtruEncPrivKey *key);

uint16_t ntru_pub_len(const NtruEncParams *params);

uint16_t ntru_priv_len(const NtruEncParams *params);

uint8_t ntru_params_from_key_pair(NtruEncKeyPair *kp, NtruEncParams *params);

uint8_t ntru_params_from_priv_key(NtruEncPrivKey *key, NtruEncParams *params);

#endif   /* NTRU_KEY_H */
