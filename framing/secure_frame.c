#include "secure_frame.h"
#include "../keymgmt/ctr_state.h"
#include "../crypto/lea.h"
#include "../crypto/lea_ctr.h"
#include "../crypto/hmac_lsh.h"
#include <string.h>

/* 표준 Modbus CRC16 (다항식 0xA001, 하위 바이트 먼저 전송)
   이 모듈이 독립적으로 동작해야 하므로 512바이트 테이블을 끌어오지 않았을 뿐, modbus-rtu.c의 테이블 기반 crc16()과 알고리즘은 같다. */
uint16_t secure_frame_crc16(const uint8_t *buf, size_t len)
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
    crc = secure_frame_crc16(plaintext_adu, SECURE_FRAME_ADDR_LEN + pdu_len);
    plaintext_adu[SECURE_FRAME_ADDR_LEN + pdu_len] = (uint8_t) (crc & 0xFF);
    plaintext_adu[SECURE_FRAME_ADDR_LEN + pdu_len + 1] = (uint8_t) (crc >> 8);
    adu_len = SECURE_FRAME_ADDR_LEN + pdu_len + SECURE_FRAME_CRC_LEN;

    /* ctr_high는 로컬에만 보관되고 절대 전송되지 않는 논스 확장값이며, 양단은 대역 외 경로로 동일한 값을 미리 설정받아야 함.
    ctr_state가 관리하는 것은 원래대로라면 전송될 하위 워드 뿐인데
       해당 환경에서 ctr이 전송되지 않으므로, ctr_low는 순전히 내부 키스트림 위치일 뿐이며 수신 측은 동일한
       시퀀스를 재구성해야 함. */
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

secure_frame_status_t secure_frame_verify_and_decrypt(const uint8_t *wire,
                                                        size_t wire_len,
                                                        uint8_t expected_addr,
                                                        key_direction_t dir,
                                                        uint8_t *out_addr,
                                                        size_t *out_ciphertext_len,
                                                        uint8_t *out_pdu,
                                                        size_t *out_pdu_len,
                                                        uint16_t *out_crc_calc,
                                                        uint16_t *out_crc_recv)
{
    secure_frame_t frame;
    directional_keys_t keys;
    uint8_t mac_input[SECURE_FRAME_ADDR_LEN + SECURE_FRAME_MAX_ADU];
    uint8_t expected_hmac[HMAC_LSH_FULL_SIZE];
    lea_key_schedule_t ks;
    uint8_t ctr_high[LEA_CTR_HIGH_SIZE];
    uint32_t ctr_low;
    uint8_t plaintext_adu[SECURE_FRAME_MAX_ADU];
    uint16_t crc_calc, crc_recv;

    if (!secure_frame_parse(wire, wire_len, &frame)) {
        return SECURE_FRAME_ERR_MALFORMED;
    }

    if (out_addr != NULL) {
        *out_addr = frame.addr;
    }
    if (out_ciphertext_len != NULL) {
        *out_ciphertext_len = frame.ciphertext_len;
    }

    if (expected_addr != SECURE_FRAME_ANY_ADDR && frame.addr != expected_addr) {
        return SECURE_FRAME_ERR_WRONG_ADDR;
    }

    if (key_store_lookup(frame.addr, dir, &keys) != 0) {
        return SECURE_FRAME_ERR_NO_KEY;
    }

    mac_input[0] = frame.addr;
    memcpy(mac_input + SECURE_FRAME_ADDR_LEN, frame.ciphertext, frame.ciphertext_len);
    hmac_lsh256(keys.mac_key, KEY_SIZE, mac_input, SECURE_FRAME_ADDR_LEN + frame.ciphertext_len, expected_hmac);
    if (memcmp(expected_hmac, frame.hmac, SECURE_FRAME_HMAC_LEN) != 0) {
        return SECURE_FRAME_ERR_HMAC;
    }

    memset(ctr_high, 0, sizeof(ctr_high));
    ctr_low = ctr_state_next_outgoing(frame.addr, dir, frame.ciphertext_len);
    lea_key_schedule(keys.enc_key, &ks);
    lea_ctr_crypt(&ks, ctr_high, ctr_low, 0, frame.ciphertext, plaintext_adu, frame.ciphertext_len);

    if (frame.ciphertext_len < SECURE_FRAME_CRC_LEN) {
        return SECURE_FRAME_ERR_CRC;
    }
    crc_calc = secure_frame_crc16(plaintext_adu, frame.ciphertext_len - SECURE_FRAME_CRC_LEN);
    crc_recv = (uint16_t) plaintext_adu[frame.ciphertext_len - 2] |
               ((uint16_t) plaintext_adu[frame.ciphertext_len - 1] << 8);
    if (out_crc_calc != NULL) {
        *out_crc_calc = crc_calc;
    }
    if (out_crc_recv != NULL) {
        *out_crc_recv = crc_recv;
    }
    if (crc_calc != crc_recv) {
        return SECURE_FRAME_ERR_CRC;
    }

    *out_pdu_len = frame.ciphertext_len - SECURE_FRAME_ADDR_LEN - SECURE_FRAME_CRC_LEN;
    memcpy(out_pdu, plaintext_adu + SECURE_FRAME_ADDR_LEN, *out_pdu_len);

    return SECURE_FRAME_OK;
}