/* 데이터 보안을 위한 프레임을 만들고 파싱:
   [addr(1)][ciphertext = LEA-CTR(Modbus ADU 전체: addr+PDU+CRC16)][hmac(32)]
   PDU는 기능 코드 + 데이터를 뜻한다. 암호화되는 ADU는 addr + PDU + CRC16,
   이 코드에서 PDU로부터 ADU 구성. 주소 바이트는 앞쪽에 평문으로도 남아 있는데(복호화되기 전에 프레임을 라우팅해야 하므로 필요함)
   회선상에는 평문 한 번, 암호문 안에 한 번 나타내게 됨. (secure_frame_encrypt_and_build).
   CTR 카운터는 전송되지 않으며 양쪽 끝이 keymgmt/ctr_state.h를 통해 추적.
   이 모듈은 프레임의 구조만 알고 있으며 실제 암호화/복호화/HMAC 작업은 crypto/를 호출하여 처리. */
#ifndef SECURITY_FRAMING_SECURE_FRAME_H
#define SECURITY_FRAMING_SECURE_FRAME_H

#include <stddef.h>
#include <stdint.h>
#include "../keymgmt/key_store.h"

#define SECURE_FRAME_ADDR_LEN 1
#define SECURE_FRAME_HMAC_LEN 32
#define SECURE_FRAME_CRC_LEN  2
#define SECURE_FRAME_MAX_PDU  253 /* function + data, Modbus PDU 길이 제한 */
/* addr + PDU + CRC16 (256 bytes, RTU ADU 길이 제한). */
#define SECURE_FRAME_MAX_ADU  (SECURE_FRAME_ADDR_LEN + SECURE_FRAME_MAX_PDU + SECURE_FRAME_CRC_LEN)

/* 생성될 수 있는 프레임 최대 길이 (주소 + 암호화된 ADU 길이 + HMAC 길이) */
#define SECURE_FRAME_MAX_WIRE_LEN \
    (SECURE_FRAME_ADDR_LEN + SECURE_FRAME_MAX_ADU + SECURE_FRAME_HMAC_LEN)

typedef struct {
    uint8_t addr;                          /* 평문, 라우팅용 */
    uint8_t ciphertext[SECURE_FRAME_MAX_ADU];
    size_t ciphertext_len;                 /* 암호화된 ADU 길이 */
    uint8_t hmac[SECURE_FRAME_HMAC_LEN];
} secure_frame_t;

/* frame을 [addr][ciphertext][hmac] 형태로 out에 붙임. 전체 바이트 길이를 반환. */
size_t secure_frame_build(const secure_frame_t *frame, uint8_t *out);

/* in의 len바이트를 frame으로 파싱. (ciphertext_len = len - 1(주소) - 32(hmac))
   HMAC 검증은 하지 않음. — keymgmt/의 키 자료를 대상으로 하는 별도 단계.
   len이 addr+hmac을 담기 부족하면 0을 반환. */
int secure_frame_parse(const uint8_t *in, size_t len, secure_frame_t *frame);

/* plaintext_pdu(Function code + data)를 받아 앞에 slave_addr을 붙이고 표준 Modbus CRC16(addr+PDU에 대해 계산)을
뒤에 붙여 실제 ADU로 만든 뒤, (slave_addr, dir)에 해당하는 키를 조회. 송신용 CTR 카운터로 ADU 전체를 LEA-CTR로 암호화,
addr||ciphertext에 대해 HMAC-LSH256을 계산, [addr][ciphertext][hmac]을 out에 저장.
out은 최소 SECURE_FRAME_MAX_WIRE_LEN 바이트여야 함. 회선 길이는 out_len에 기록.
성공 시 0을, 키 조회에 실패했거나 pdu_len이 너무 크면 -1을 반환 */
int secure_frame_encrypt_and_build(uint8_t slave_addr,
                                    const uint8_t *plaintext_pdu,
                                    size_t pdu_len,
                                    key_direction_t dir,
                                    uint8_t *out,
                                    size_t *out_len);

#endif /* SECURITY_FRAMING_SECURE_FRAME_H */
