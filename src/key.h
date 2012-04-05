#ifndef KEY_H
#define KEY_H

#include "ntru.h"

void ntru_export_pub(NtruEncPubKey *key, char *arr);

int ntru_import_pub(char *arr, NtruEncPubKey *key);

int ntru_export_priv(NtruEncPrivKey *key, char *arr);

void ntru_import_priv(char *arr, NtruEncPrivKey *key);

int ntru_pub_len(int N, int q);

int ntru_priv_len(int df1, int df2, int df3);

#endif
