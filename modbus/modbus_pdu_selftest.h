#ifndef SECURITY_MODBUS_MODBUS_PDU_SELFTEST_H
#define SECURITY_MODBUS_MODBUS_PDU_SELFTEST_H

/* modbus_build_response()의 8개 Function Codes 성공 경로 + 예외 코드 3종(Illegal
   Function/Address/Value) + 경계 조건(테이블 크기 128, 프로토콜 quantity 상한,
   byte_count 불일치, 요청 길이 부족)을 검증하는 자체 테스트.
   케이스마다 [PASS]/[FAIL]을 stdout에 출력하고 마지막에 통과/실패 개수를 요약한다.
   demo/test_modbus_response.c(커맨드라인 단독 실행)와 demo/main.c 옵션 3(전체
   데모 안에서 실행)이 해당 함수 공유
   반환값: 전부 통과하면 1, 하나라도 실패하면 0. */
int modbus_pdu_self_test(void);

#endif /* SECURITY_MODBUS_MODBUS_PDU_SELFTEST_H */
