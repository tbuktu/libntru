#ifndef NTRU_KEY_H
#define NTRU_KEY_H

#include "types.h"

void ntru_export_pub(NtruEncPubKey *key, uint8_t *arr);

uint16_t ntru_import_pub(uint8_t *arr, NtruEncPubKey *key);

uint16_t ntru_export_priv(NtruEncPrivKey *key, uint8_t *arr);

void ntru_import_priv(uint8_t *arr, NtruEncPrivKey *key);

uint16_t ntru_pub_len(uint16_t N, uint16_t q);

uint16_t ntru_priv_len(uint16_t df1, uint16_t df2, uint16_t df3);

#endif   /* NTRU_KEY_H */
