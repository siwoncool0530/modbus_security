#include "secure_frame.h"
#include "../keymgmt/ctr_state.h"
#include "../crypto/lea.h"
#include "../crypto/lea_ctr.h"
#include "../crypto/hmac_lsh.h"
#include <string.h>

/* 표준 Modbus CRC16 (다항식 0xA001, 하위 바이트 먼저 전송)
   이 모듈이 독립적으로 동작해야 하므로 512바이트 테이블을 끌어오지 않았을 뿐, modbus-rtu.c의 테이블 기반 crc16()과 알고리즘은 같다. */
static uint16_t modbus_crc16(const uint8_t *buf, size_t len)
{
    uint16_t crc = 0xFFFF;
    size_t i;
    int bit;

    for (i = 0; i < len; i++) {
        crc ^= buf[i];
        for (bit = 0; bit < 8; bit++) {
            if (crc & 1) {
                crc = (uint16_t) ((crc >> 1) ^ 0xA001);
            } else {
                crc = (uint16_t) (crc >> 1);
            }
        }
    }
    return crc;
}

size_t secure_frame_build(const secure_frame_t *frame, uint8_t *out)
{
    size_t pos = 0;

    out[pos++] = frame->addr;

    memcpy(out + pos, frame->ciphertext, frame->ciphertext_len);
    pos += frame->ciphertext_len;

    memcpy(out + pos, frame->hmac, SECURE_FRAME_HMAC_LEN);
    pos += SECURE_FRAME_HMAC_LEN;

    return pos;
}

int secure_frame_parse(const uint8_t *in, size_t len, secure_frame_t *frame)
{
    size_t min_len = SECURE_FRAME_ADDR_LEN + SECURE_FRAME_HMAC_LEN;
    size_t ciphertext_len;

    if (len < min_len) {
        return 0;
    }

    ciphertext_len = len - min_len;
    if (ciphertext_len > SECURE_FRAME_MAX_ADU) {
        return 0;
    }

    frame->addr = in[0];
    frame->ciphertext_len = ciphertext_len;
    memcpy(frame->ciphertext, in + SECURE_FRAME_ADDR_LEN, ciphertext_len);
    memcpy(frame->hmac, in + SECURE_FRAME_ADDR_LEN + ciphertext_len, SECURE_FRAME_HMAC_LEN);

    return 1;
}

int secure_frame_encrypt_and_build(uint8_t slave_addr,
                                    const uint8_t *plaintext_pdu,
                                    size_t pdu_len,
                                    key_direction_t dir,
                                    uint8_t *out,
                                    size_t *out_len)
{
    directional_keys_t keys;
    lea_key_schedule_t ks;
    uint8_t ctr_high[LEA_CTR_HIGH_SIZE];
    uint32_t ctr_low;
    secure_frame_t frame;
    uint8_t plaintext_adu[SECURE_FRAME_MAX_ADU];
    size_t adu_len;
    uint16_t crc;
    uint8_t mac_input[SECURE_FRAME_ADDR_LEN + SECURE_FRAME_MAX_ADU];

    if (pdu_len > SECURE_FRAME_MAX_PDU) {
        return -1;
    }
    if (key_store_lookup(slave_addr, dir, &keys) != 0) {
        return -1;
    }

    /* 순수 PDU를 실제 Modbus RTU ADU로 변환: addr + PDU + CRC16
       (CRC는 암호화되지 않은 RTU 회선에서와 마찬가지로 addr+PDU를 포함하여 계산).
       주소를 포함한 이 ADU 전체가 아래에서 암호화되는 대상이며, 바깥쪽 프레임의 평문 addr 바이트는 오직 라우팅 목적으로만 존재함 */
    plaintext_adu[0] = slave_addr;
    memcpy(plaintext_adu + SECURE_FRAME_ADDR_LEN, plaintext_pdu, pdu_len);
    crc = modbus_crc16(plaintext_adu, SECURE_FRAME_ADDR_LEN + pdu_len);
    plaintext_adu[SECURE_FRAME_ADDR_LEN + pdu_len] = (uint8_t) (crc & 0xFF);
    plaintext_adu[SECURE_FRAME_ADDR_LEN + pdu_len + 1] = (uint8_t) (crc >> 8);
    adu_len = SECURE_FRAME_ADDR_LEN + pdu_len + SECURE_FRAME_CRC_LEN;

    /* ctr_high는 로컬에만 보관되고 절대 전송되지 않는 논스 확장값이며, 양단은 대역 외 경로로 동일한 값을 미리 설정받아야 함.
    ctr_state가 관리하는 것은 원래대로라면 전송될 하위 워드 뿐인데
       - 사실 여기서는 그것도 전송되지 않으므로, ctr_low는 순전히 내부 키스트림 위치일 뿐이며 수신 측은 동일한
       시퀀스를 추적하여 이를 재구성해야 함. */
    memset(ctr_high, 0, sizeof(ctr_high));
    ctr_low = ctr_state_next_outgoing(slave_addr, dir, adu_len);

    lea_key_schedule(keys.enc_key, &ks);
    frame.addr = slave_addr;
    frame.ciphertext_len = adu_len;
    lea_ctr_crypt(&ks, ctr_high, ctr_low, 1, plaintext_adu, frame.ciphertext, adu_len);

    mac_input[0] = frame.addr;
    memcpy(mac_input + SECURE_FRAME_ADDR_LEN, frame.ciphertext, adu_len);
    hmac_lsh256(keys.mac_key, KEY_SIZE, mac_input, SECURE_FRAME_ADDR_LEN + adu_len, frame.hmac);

    *out_len = secure_frame_build(&frame, out);
    return 0;
}