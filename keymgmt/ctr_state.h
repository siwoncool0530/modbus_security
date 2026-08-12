/* 방향별 CTR 카운터 관리: 다음 송신 카운터 값, 지금까지 수신 허용된 최댓값, 그리고 재부팅해도
   동일한 키로 이미 사용된 카운터 값을 절대 재사용하지 않도록 함 */
#ifndef SECURITY_KEYMGMT_CTR_STATE_H
#define SECURITY_KEYMGMT_CTR_STATE_H

#include <stddef.h>
#include <stdint.h>
#include "key_store.h"

/* (slave_addr, dir)에 대해 아직 사용되지 않은 다음 송신 카운터 값을 반환하고 저장된 카운터를 증가시킴.
   새 메시지마다 한 번씩만 호출 — 같은 메시지를 재전송할 때는 이 함수를 다시 호출해서는 안됨.
   msg_len은 이 카운터로 암호화될 평문 ADU의 바이트 길이 (lea_ctr_crypt에 넘길 len과 동일).
   LEA-CTR은 16바이트 블록마다 카운터를 1씩 증가시키므로, 반환값부터
   ceil(msg_len/16)개의 연속된 카운터 값이 이번 메시지에서 소비됨 -- 그만큼을 예약해
   다음 메시지가 그 범위와 겹치지 않도록 함. (msg_len 대신 매번 1만 증가시키면 16바이트를
   넘는 메시지의 뒤쪽 블록이 다음 메시지의 카운터와 겹쳐 키스트림이 재사용됨.) */
uint32_t ctr_state_next_outgoing(uint8_t slave_addr, key_direction_t dir, size_t msg_len);

/* (slave_addr, dir)에 대해 수신 카운터 값을 검증:
   - ctr < highest_accepted 이면 거부 (재전송 공격)
   - ctr == highest_accepted 이면 허용 (정상적인 재시도이며, 호출자는 새 메시지로 취급하지 말고 재처리 필요)
   - ctr > highest_accepted 이면 허용하고 저장된 상한값을 갱신
   프레임을 처리해야 하면 1을, 거부해야 하면 0을 반환. */
int ctr_state_validate_incoming(uint8_t slave_addr, key_direction_t dir, uint32_t ctr);

/* 현재 카운터 상태를 비휘발성 저장소에 저장. 재시작 후 카운터 값이 실제로 재사용되기 전에 충분한 여유를 두고 호출.
   현재는 안전 여유를 두고 일괄 처리하는 대신 ctr_state_next_outgoing()을 호출할 때마다 단순히 즉시 기록하는 방식.
   테스트에는 문제없지만, 실제 트래픽을 처리하기 전에 재검토 필요 */
int ctr_state_persist(void);

/* 시작 시 비휘발성 저장소에서 카운터 상태를 불러옴.
   상태 파일을 찾아서 불러왔으면 0을, 없었으면 -1을 반환
   (-1이어도 문제없음 - 카운터가 처음 필요해지는 시점에 key_store의 키별 initial_ctr로 대체). */
int ctr_state_load(void);

/* ctr_state_load()/ctr_state_persist()가 현재 디렉터리의 기본값인 "ctr_state.dat" 대신 특정 파일을 사용하도록 지정 */
void ctr_state_set_path(const char *path);

#endif /* SECURITY_KEYMGMT_CTR_STATE_H */
