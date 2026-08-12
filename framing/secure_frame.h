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

typedef enum {
    SECURE_FRAME_OK = 0,
    SECURE_FRAME_ERR_MALFORMED = -1,  /* addr+hmac을 담기에도 부족한 길이 */
    SECURE_FRAME_ERR_WRONG_ADDR = -2, /* expected_addr을 지정했는데 frame.addr이 다름 */
    SECURE_FRAME_ERR_NO_KEY = -3,     /* key_store에 등록된 키 없음 */
    SECURE_FRAME_ERR_HMAC = -4,       /* HMAC 불일치 */
    SECURE_FRAME_ERR_CRC = -5,        /* 복호화 후 CRC16 불일치 (카운터 어긋남 의심) */
} secure_frame_status_t;

/* expected_addr에 이 값을 넘기면 주소 필터를 건너뜀 (유효 slave addr 최댓값은 247). */
#define SECURE_FRAME_ANY_ADDR 0xFFu

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

/* secure_frame_encrypt_and_build()의 역방향: wire의 wire_len바이트를 파싱하고, 필요하면
   주소를 검사하고, (frame.addr, dir)에 해당하는 키로 HMAC을 검증한 뒤 LEA-CTR로 복호화하고
   CRC16을 검증하여 순수 PDU(주소/CRC 제거됨)를 out_pdu에 남긴다.

   expected_addr이 SECURE_FRAME_ANY_ADDR이 아니면, 파싱된 frame.addr이 이 값과 다를 경우
   키 조회/복호화를 시도하지 않고 SECURE_FRAME_ERR_WRONG_ADDR을 바로 반환 (RS-485 버스에
   여러 슬레이브가 물려 있을 때, 우리 주소가 아닌 프레임을 걸러내기 위함).

   out_addr에는 (성공/실패와 무관하게 파싱이 됐다면) frame.addr이 채워짐.
   out_ciphertext_len/out_crc_calc/out_crc_recv는 선택 사항(NULL 허용)으로, 호출자가 진단
   메시지에 필요한 세부 정보(파싱 직후의 암호문 길이, CRC 불일치 시 계산값/수신값)를
   얻을 수 있도록 두었다. out_pdu는 최소 SECURE_FRAME_MAX_PDU 바이트여야 함.

   SECURE_FRAME_OK를 반환하면 out_pdu/out_pdu_len이 유효함. 그 외에는 해당하는
   secure_frame_status_t 오류 코드를 반환. */
secure_frame_status_t secure_frame_verify_and_decrypt(const uint8_t *wire,
                                                        size_t wire_len,
                                                        uint8_t expected_addr,
                                                        key_direction_t dir,
                                                        uint8_t *out_addr,
                                                        size_t *out_ciphertext_len,
                                                        uint8_t *out_pdu,
                                                        size_t *out_pdu_len,
                                                        uint16_t *out_crc_calc,
                                                        uint16_t *out_crc_recv);

/* 표준 Modbus CRC16 (다항식 0xA001, 하위 바이트 먼저 전송). do_self_test()류의 호출자가
   secure_frame_encrypt_and_build()를 거치지 않고 직접 테스트 ADU를 구성할 때 필요하므로
   공개 함수로 노출. */
uint16_t secure_frame_crc16(const uint8_t *buf, size_t len);

#endif /* SECURITY_FRAMING_SECURE_FRAME_H */
