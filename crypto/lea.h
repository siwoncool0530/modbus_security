/* LEA-128 키 스케줄. */
#ifndef SECURITY_CRYPTO_LEA_H
#define SECURITY_CRYPTO_LEA_H

#include <stdint.h>
#include "lea_ref/lea.h"

#define LEA_KEY_SIZE 16

typedef LEA_KEY lea_key_schedule_t;

/* Expands a 128-bit key into round keys. */
void lea_key_schedule(const uint8_t key[LEA_KEY_SIZE], lea_key_schedule_t *ks);

#endif /* SECURITY_CRYPTO_LEA_H */
