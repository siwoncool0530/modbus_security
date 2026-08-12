/* LEA-CTR */
#ifndef SECURITY_CRYPTO_LEA_CTR_H
#define SECURITY_CRYPTO_LEA_CTR_H

#include <stddef.h>
#include <stdint.h>
#include "lea.h"

#define LEA_CTR_HIGH_SIZE 12 /* locally-held, non-transmitted counter bytes */
#define LEA_CTR_LOW_SIZE  4  /* transmitted-per-frame counter bytes */

/* 키 스케줄 ks와 카운터 블록(ctr_high || ctr_low)을 사용하여 in의 len 바이트를 LEA-CTR로 암호화/복호화하고
   결과를 out에 씀. is_encrypt는 참조 구현 호출 시 LEA_CTR_ENC와 LEA_CTR_DEC 중 무엇을 선택할지 결정
   - CTR의 XOR 연산은 어느 방향이든 대칭이지만, lea_ref의 API가 명시적인 방향 상수를 요구하기 때문에 구분
*/
void lea_ctr_crypt(const lea_key_schedule_t *ks,
                    const uint8_t ctr_high[LEA_CTR_HIGH_SIZE],
                    uint32_t ctr_low,
                    int is_encrypt,
                    const uint8_t *in,
                    uint8_t *out,
                    size_t len);

#endif /* SECURITY_CRYPTO_LEA_CTR_H */
