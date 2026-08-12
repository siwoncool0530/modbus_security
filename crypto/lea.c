#include "lea.h"

void lea_key_schedule(const uint8_t key[LEA_KEY_SIZE], lea_key_schedule_t *ks)
{
    lea_set_key(ks, key, LEA_KEY_SIZE);
}
