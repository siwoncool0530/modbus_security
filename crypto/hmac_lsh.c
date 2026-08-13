#include "hmac_lsh.h"
#include <string.h>

/* hmac_lsh_digest()의 databytelen은 BYTE 단위 */

void hmac_lsh256(const uint8_t *key,
                  size_t key_len,
                  const uint8_t *msg,
                  size_t msg_len,
                  uint8_t out[HMAC_LSH_FULL_SIZE])
{
    hmac_lsh_digest(LSH_TYPE_256, key, key_len, msg, msg_len, out);
}