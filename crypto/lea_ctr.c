#include "lea_ctr.h"
#include <string.h>

void lea_ctr_crypt(const lea_key_schedule_t *ks,
                    const uint8_t ctr_high[LEA_CTR_HIGH_SIZE],
                    uint32_t ctr_low,
                    int is_encrypt,
                    const uint8_t *in,
                    uint8_t *out,
                    size_t len)
{
    LEA_ONLINE_CTX ctx;
    uint8_t ctr_block[LEA_CTR_HIGH_SIZE + LEA_CTR_LOW_SIZE];
    int n, total = 0;

    memcpy(ctr_block, ctr_high, LEA_CTR_HIGH_SIZE);
    ctr_block[LEA_CTR_HIGH_SIZE + 0] = (uint8_t) (ctr_low >> 24);
    ctr_block[LEA_CTR_HIGH_SIZE + 1] = (uint8_t) (ctr_low >> 16);
    ctr_block[LEA_CTR_HIGH_SIZE + 2] = (uint8_t) (ctr_low >> 8);
    ctr_block[LEA_CTR_HIGH_SIZE + 3] = (uint8_t) (ctr_low);

    lea_online_init_ex(&ctx, is_encrypt ? LEA_CTR_ENC : LEA_CTR_DEC, ctr_block, ks);
    n = lea_online_update(&ctx, out, (uint8_t *) in, (int) len);
    total += n;
    n = lea_online_final(&ctx, out + total);
    total += n;
}
