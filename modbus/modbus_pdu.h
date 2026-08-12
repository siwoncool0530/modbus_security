/* 순수 Modbus PDU 로직: 함수 코드, 코일/레지스터 데이터 모델, 예외 응답.
   프레임 암호화(framing/)나 키 관리(keymgmt/)는 전혀 모르며, "암호화될 내용물"만 다룸 --
   secure_frame.c가 "봉투 구조"만 알고 내용물을 모르는 것과 대칭되는 역할.
   지원 함수 코드 8종: 0x01 Read Coils, 0x02 Read Discrete Inputs, 0x03 Read Holding
   Registers, 0x04 Read Input Registers, 0x05 Write Single Coil, 0x06 Write Single
   Register, 0x0F Write Multiple Coils, 0x10 Write Multiple Registers. */
#ifndef SECURITY_MODBUS_MODBUS_PDU_H
#define SECURITY_MODBUS_MODBUS_PDU_H

#include <stdint.h>
#include <stddef.h>

#define MODBUS_FUNC_READ_COILS               0x01
#define MODBUS_FUNC_READ_DISCRETE_INPUTS     0x02
#define MODBUS_FUNC_READ_HOLDING_REGISTERS   0x03
#define MODBUS_FUNC_READ_INPUT_REGISTERS     0x04
#define MODBUS_FUNC_WRITE_SINGLE_COIL        0x05
#define MODBUS_FUNC_WRITE_SINGLE_REGISTER    0x06
#define MODBUS_FUNC_WRITE_MULTIPLE_COILS     0x0F
#define MODBUS_FUNC_WRITE_MULTIPLE_REGISTERS 0x10

/* 응답 PDU의 함수 코드에 이 비트가 서 있으면 예외 응답 (그 다음 한 바이트가 예외 코드). */
#define MODBUS_EXCEPTION_BIT 0x80

#define MODBUS_EXCEPTION_ILLEGAL_FUNCTION     0x01
#define MODBUS_EXCEPTION_ILLEGAL_DATA_ADDRESS 0x02
#define MODBUS_EXCEPTION_ILLEGAL_DATA_VALUE   0x03

/* 데모용 코일/레지스터 개수(주소 0..MODBUS_TABLE_SIZE-1). 실제 슬레이브의 레지스터 맵
   크기와 무관 -- 이 범위를 벗어난 요청은 Illegal Data Address 예외로 정상 처리됨. */
#define MODBUS_TABLE_SIZE 128

/* libmodbus(../../libmodbus-master/src/modbus.h)와 동일한 프로토콜 규격상의 quantity 상한. */
#define MODBUS_MAX_READ_BITS      2000
#define MODBUS_MAX_WRITE_BITS     1968
#define MODBUS_MAX_READ_REGISTERS 125
#define MODBUS_MAX_WRITE_REGISTERS 123

/* config에서 고른 function code/시작주소/값-또는-수량으로 요청 PDU를 만든다.
   value_or_qty 해석은 함수 코드에 따라 다름:
     0x01/0x02/0x03/0x04 (읽기)   : 읽을 개수
     0x05 (단일 코일 쓰기)         : 0=OFF, 0이 아니면 ON
     0x06 (단일 레지스터 쓰기)     : 레지스터 값(0-65535)
     0x0F (다중 코일 쓰기)         : 쓸 코일 개수 -- 값은 인덱스 기반으로 자동 생성
     0x10 (다중 레지스터 쓰기)     : 쓸 레지스터 개수 -- 값은 인덱스 기반으로 자동 생성
   지원하지 않는 함수 코드이거나 프로토콜 quantity 상한(MODBUS_MAX_*)을 초과하면 0을 반환.
   성공 시 1을 반환하고 out_pdu/out_pdu_len을 채움 (out_pdu는 최소 SECURE_FRAME_MAX_PDU 바이트).
   주소 범위(내부 데이터 모델 크기) 검사는 여기서 하지 않음 -- 실제 마스터가 슬레이브의
   정확한 레지스터 맵을 미리 안다고 가정하지 않는 것과 같은 이유이며, 범위를 벗어나면
   슬레이브가 modbus_build_response()에서 Illegal Data Address 예외로 정상 응답한다. */
int modbus_build_request(uint8_t func, uint16_t addr, uint16_t value_or_qty,
                          uint8_t *out_pdu, size_t *out_pdu_len);

/* 복호화된 요청 PDU(함수 코드 + 데이터)를 해석해 내부 코일/레지스터 모델에 적용(쓰기)
   또는 조회(읽기)하고, 그 결과로 회신 PDU(정상 응답 또는 Modbus 예외 응답)를 만든다.
   req_pdu/req_len: secure_frame_verify_and_decrypt()가 돌려준 out_pdu/out_pdu_len 그대로.
   resp_pdu는 최소 SECURE_FRAME_MAX_PDU 바이트여야 함.
   req_len이 0이면(함수 코드조차 없음) 회신을 만들 수 없으므로 0을 반환 -- 호출자는 오늘처럼
   회신을 생략해야 함. 그 외에는 항상 1을 반환하며, resp_pdu에 다음 중 하나가 담긴다:
     - 정상 응답: 함수 코드를 인식했고 요청 형식과 주소/수량이 모두 유효한 경우
     - 예외 응답(함수코드|MODBUS_EXCEPTION_BIT + 예외코드): 함수 코드가 8종 밖이면
       Illegal Function, 내부 모델 범위를 벗어나면 Illegal Data Address, 요청 길이가
       그 함수 코드의 필수 필드보다 짧거나 quantity/byte_count가 잘못됐으면
       Illegal Data Value */
int modbus_build_response(const uint8_t *req_pdu, size_t req_len,
                           uint8_t *resp_pdu, size_t *resp_len);

#endif /* SECURITY_MODBUS_MODBUS_PDU_H */
