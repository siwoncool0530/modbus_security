/* LSH-256을 기반 해시로 사용하는 HMAC 구성. 실제로 키 기반 인증을 제공
   —> lsh.h 단독으로는 키가 없어 발신자에 대해 증명하지 못함 */
#ifndef SECURITY_CRYPTO_HMAC_LSH_H
#define SECURITY_CRYPTO_HMAC_LSH_H

#include <stddef.h>
#include <stdint.h>
#include "lsh_ref/include/hmac.h"

#define HMAC_LSH_FULL_SIZE 32
#define HMAC_LSH_MAC_SIZE  16 /* 필요시 버릴 길이 */

/* Computes HMAC-LSH256(key, msg) and writes the full 32-byte tag to out. */
void hmac_lsh256(const uint8_t *key,
                  size_t key_len,
                  const uint8_t *msg,
                  size_t msg_len,
                  uint8_t out[HMAC_LSH_FULL_SIZE]);

#endif /* SECURITY_CRYPTO_HMAC_LSH_H */
