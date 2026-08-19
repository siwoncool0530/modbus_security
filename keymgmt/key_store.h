/* slave별 키 테이블: 방향별로 분리된 암호화/MAC 키와 공유 브로드캐스트 키
   키는 slave addr로 조회 */
#ifndef SECURITY_KEYMGMT_KEY_STORE_H
#define SECURITY_KEYMGMT_KEY_STORE_H

#include <stdint.h>
#include "../crypto/lea.h"

#define KEY_SIZE 16

typedef enum {
    DIR_MASTER_TO_SLAVE,
    DIR_SLAVE_TO_MASTER,
    DIR_BROADCAST
} key_direction_t;

typedef struct {
    uint8_t enc_key[KEY_SIZE];
    uint8_t mac_key[KEY_SIZE];
} directional_keys_t;

/* key_direction_t를 0..2 테이블 인덱스로 매핑 - key_store와 ctr_state 둘 다
   (addr, dir) 테이블을 병렬로 색인하므로 이 매핑을 공유. 성공 시 0을 반환하고
   out을 채우며, dir이 잘못된 값이면 -1을 반환. */
int key_direction_index(key_direction_t dir, int *out);

/* 주어진 방향에서 slave_addr에 대한 암호화/MAC 키 쌍을 조회.
   성공 시 0을 반환하고 out을 채우며, slave addr이 등록되어 있지 않으면 -1을 반환. */
int key_store_lookup(uint8_t slave_addr, key_direction_t dir, directional_keys_t *out);

/* 주어진 방향에서 slave_addr의 키 쌍을 등록(또는 교체) — 최초 1회 호출. */
int key_store_provision(uint8_t slave_addr, key_direction_t dir, const directional_keys_t *keys);

/* 키 소스 불러오기
   텍스트 파일에서 키를 불러오며, 한 줄에 항목 하나씩 다음 형식으로 기록:
   "<addr> <dir> <enc_key:16자> <mac_key:16자> <initial_ctr:16진수 8자>"
   여기서 <dir>는 m2s/s2m/bc이고 키 필드는 16진수로 디코딩하지 않은 원본 ASCII 바이트 그대로.
   예: 1 m2s 1234567890123456 abcdefghijklmnop 00000000
   '#'로 시작하는 줄(주석)과 빈 줄은 건너뜀. 테스트 도중 실제 키 관리 시스템을 대신함.
   불러온 항목 수를 반환하며, 파일을 열 수 없으면 -1을 반환. */
int key_store_load_file(const char *path);

/* slave_addr/dir의 키와 함께 주어진 초기 CTR 값(key_store_load_file() 줄의 마지막 열)을 반환.
   ctr_state가 처음 필요한 시점에 새 카운터를 시드하는 데 사용.
   성공 시 0을 반환하고 out을 채우며, 등록되어 있지 않으면 -1을 반환. */
int key_store_get_initial_ctr(uint8_t slave_addr, key_direction_t dir, uint32_t *out);

#endif /* SECURITY_KEYMGMT_KEY_STORE_H */
