# security 소스코드 사용 매뉴얼

ver 1.0

## 차례

1. [개요](#1-개요)
2. [소스코드 구성](#2-소스코드-구성)
3. [빌드 방법](#3-빌드-방법)
4. [인터페이스](#4-인터페이스)
   - 4.1 [crypto/ (얇은 래퍼)](#41-crypto-얇은-래퍼)
   - 4.2 [keymgmt/key_store.h](#42-keymgmtkey_storeh)
   - 4.3 [keymgmt/ctr_state.h](#43-keymgmtctr_stateh)
   - 4.4 [framing/secure_frame.h](#44-framingsecure_frameh)
   - 4.5 [modbus/modbus_pdu.h](#45-modbusmodbus_pduh)
   - 4.6 [demo/ 공용 유틸리티](#46-demo-공용-유틸리티)
5. [데모 프로그램 사용법](#5-데모-프로그램-사용법)
6. [테스트 방법](#6-테스트-방법)

---

## 1. 개요

`security/`는 Modbus RTU 통신에 기밀성(암호화)과 무결성/인증(HMAC)을 더하는 보안 래퍼로, LEA-CTR 암호화와 HMAC-LSH256 인증을 사용한다. LEA와 LSH 알고리즘 자체의 상세 규격/구현은 별도의 공식 매뉴얼(`블록암호 LEA 소스코드 사용 매뉴얼`, `해시함수 LSH 소스코드 사용 매뉴얼`)에 문서화되어 있으므로, 이 문서는 그 위에 이 프로젝트가 직접 구현한 계층만 다룬다.

### 계층 구조

```
crypto/    LEA, LSH/HMAC 원시 함수 (얇은 래퍼만 이 문서에서 다룸, §4.1)
keymgmt/   키 테이블 + 방향별(m2s/s2m/bc) CTR 카운터 상태
framing/   [addr|ciphertext|hmac] 와이어 프레임 구조 -- 내용물(PDU)이 뭔지는 모름
modbus/    PDU 내용물 (함수 코드, 코일/레지스터 데이터 모델, 예외 응답) -- 암호화는 전혀 모름
demo/      위 계층들을 엮은 실행 가능한 도구 (인터랙티브 도구 + 두 개의 배치 데모)
```

각 계층은 자신의 바로 아래 계층만 알고, 위 계층은 전혀 모른다. 예를 들어 `framing/`은 PDU 안에 Modbus 함수 코드가 들어있다는 사실 자체를 모르고, `modbus/`는 그 PDU가 암호화되어 전송된다는 사실을 모른다.

### 와이어 프레임 구조

```
[addr(1)][ciphertext = LEA-CTR(addr + PDU + CRC16)][hmac(32)]
```

- `addr`: 평문으로 한 번 더 앞에 붙음 -- 복호화 전에 프레임을 라우팅해야 하므로 필요.
- `ciphertext`: 실제 Modbus ADU(주소+PDU+CRC16) 전체를 LEA-CTR로 암호화한 것. CTR 카운터 자체는 전송되지 않고 양쪽 끝이 `keymgmt/ctr_state.h`로 각자 추적.
- `hmac`: `addr || ciphertext`에 대한 HMAC-LSH256 (32바이트).

---

## 2. 소스코드 구성

### crypto/ (LEA, LSH 원본 + 이 프로젝트의 얇은 래퍼)

| 파일명 | 내용 |
|---|---|
| `lea.h`/`lea.c` | LEA 키 스케줄 얇은 래퍼 (`lea_key_schedule`) |
| `lea_ctr.h`/`lea_ctr.c` | LEA-CTR 암/복호화 얇은 래퍼 |
| `hmac_lsh.h`/`hmac_lsh.c` | HMAC-LSH256 얇은 래퍼 |
| `lea_ref/` | 벤더 제공 LEA 참조 구현 (SIMD 백엔드 포함) |
| `lsh_ref/` | 벤더 제공 LSH/HMAC 참조 구현 |

### keymgmt/ — 키 테이블과 카운터 상태

| 파일명 | 내용 |
|---|---|
| `key_store.h`/`key_store.c` | slave별/방향별 암호화·MAC 키 테이블, `keys.txt` 로더 |
| `ctr_state.h`/`ctr_state.c` | slave별/방향별 CTR 카운터 상태 (송신 카운터, 수신 최댓값, 영속화) |
| `keys.txt` | 테스트/커미셔닝용 키 소스 파일 |

### framing/ — 와이어 프레임 구조

| 파일명 | 내용 |
|---|---|
| `secure_frame.h`/`secure_frame.c` | `[addr\|ciphertext\|hmac]` 프레임 조립/파싱, 암호화+HMAC 결합(`encrypt_and_build`), 복호화+HMAC 검증 결합(`verify_and_decrypt`) |

### modbus/ — Modbus PDU 로직

| 파일명 | 내용 |
|---|---|
| `modbus_pdu.h`/`modbus_pdu.c` | 함수 코드 8종의 요청/응답 PDU 조립, 데모용 코일/레지스터 데이터 모델, Modbus 예외 응답 |

### demo/ — 실행 가능한 도구와 공용 유틸리티

| 파일명 | 내용 |
|---|---|
| `main.c` | 대화형 인터랙티브 도구(`secure_demo`) -- 마스터/슬레이브 모드, 키 초기화, 셀프 테스트, 환경 설정, 실행 |
| `secure_send_demo.c` | 배치 송신 데모(`secure_send_demo`) -- 프레임 크기 1~123레지스터를 훑으며 프레이밍 스트레스 테스트 |
| `secure_recv_demo.c` | 배치 수신 데모(`secure_recv_demo`) -- 실제 하드웨어로 왕복 검증 |
| `serial_port.h`/`serial_port.c` | COM/tty 포트 열기/읽기/쓰기, Modbus T3.5 유휴 간격 계산(`modbus_t35_us`) |
| `key_paths.h`/`key_paths.c` | 실행 파일 상대 경로 계산, `keys.txt` 탐색 (세 실행 파일 공통) |
| `demo_log.h`/`demo_log.c` | 파일 로깅 유틸리티 (`secure_send_demo`/`secure_recv_demo` 전용, `main.c`는 미사용) |
| `rs485_probe.c` | 커널 RS-485 드라이버 지원 여부를 확인하는 독립 진단 도구 (수동 빌드, `make`에 포함 안 됨) |

---

## 3. 빌드 방법

### Makefile 대상

```
make            # secure_send_demo, secure_recv_demo, secure_demo 세 개 모두 빌드
make clean      # 빌드 산출물 정리
make NO_NEON=1  # (aarch64/armv7l에서) NEON 대신 이식 가능한 일반 C 경로로 폴백
```

### 아키텍처 자동 감지 (`ARCH := $(shell uname -m)`)

| ARCH | LEA SIMD 백엔드 | 비고 |
|---|---|---|
| `aarch64` | NEON (`NO_NEON=1`이면 일반 C) | 실제 타겟(Raspberry Pi 5 / CM5) |
| `armv7l` | NEON (`NO_NEON=1`이면 일반 C) | |
| 그 외(x86_64 등) | 일반 C만 (SIMD 없음) | 개발용 sanity-check 빌드 -- x86 SIMD 백엔드는 이 저장소 자체 빌드 과정에서 검증되지 않아 의도적으로 미사용 |

### `make`가 없는 환경(예: Windows)의 수동 빌드

```bash
gcc -O2 -Wall -DNO_AVX2 -DNO_XOP -DNO_PCLMUL -DNO_SSE2 \
  demo/main.c \
  framing/secure_frame.c keymgmt/key_store.c keymgmt/ctr_state.c \
  crypto/lea.c crypto/lea_ctr.c crypto/hmac_lsh.c \
  crypto/lsh_ref/src/lsh.c crypto/lsh_ref/src/lsh256.c crypto/lsh_ref/src/lsh512.c crypto/lsh_ref/src/hmac.c \
  crypto/lea_ref/lea_base.c crypto/lea_ref/lea_core.c crypto/lea_ref/lea_online.c \
  crypto/lea_ref/lea_gcm_generic.c crypto/lea_ref/lea_t_fallback.c crypto/lea_ref/lea_t_generic.c \
  crypto/lea_ref/cpu_info_ia32.c \
  demo/serial_port.c demo/key_paths.c modbus/modbus_pdu.c \
  -o secure_demo.exe -lws2_32
```

`secure_send_demo`/`secure_recv_demo`를 만들 때는 `demo/main.c`를 `demo/secure_send_demo.c`(또는 `secure_recv_demo.c`)로 바꾸고 `demo/demo_log.c`를 추가한다. `secure_recv_demo`는 `modbus/modbus_pdu.c`도 필요하지만 `secure_send_demo`는 필요 없다(아래 표 참고).

### 실행 파일별 필요 오브젝트

세 실행 파일은 공통 오브젝트(`$(LIB_OBJS)`: `framing/`+`keymgmt/`+`crypto/`+`demo/serial_port.c`+`demo/key_paths.c`)를 공유하되, 두 그룹은 필요한 곳에만 링크된다 (임베디드 타겟의 바이너리 크기를 불필요하게 늘리지 않기 위함):

| 실행 파일 | `$(LIB_OBJS)` | `demo_log.o` | `modbus_pdu.o` |
|---|:---:|:---:|:---:|
| `secure_demo` (main.c) | ✅ | ❌ (자체 콘솔 전용 `print_hex` 사용) | ✅ (마스터=요청 생성, 슬레이브=응답 생성) |
| `secure_send_demo` | ✅ | ✅ | ❌ (슬레이브 역할 없음, 고정 함수 0x10 스윕만 함) |
| `secure_recv_demo` | ✅ | ✅ | ✅ (슬레이브=응답 생성) |

---

## 4. 인터페이스

### 4.1 crypto/ (얇은 래퍼)

LEA/LSH 알고리즘 자체의 상세 규격은 각 알고리즘의 공식 매뉴얼을 참고. 여기서는 이 프로젝트가 호출하는 얇은 래퍼의 입출력만 기록한다.

**`void lea_key_schedule(const uint8_t key[16], lea_key_schedule_t *ks)`**
입력: 16바이트 LEA-128 마스터키. 출력: `ks`에 라운드 키 채움.

**`void hmac_lsh256(const uint8_t *key, size_t key_len, const uint8_t *msg, size_t msg_len, uint8_t out[32])`**
입력: MAC 키, 메시지. 출력: `out`에 32바이트 HMAC-LSH256 태그.

**`void hmac_lsh256_truncated(const uint8_t *key, size_t key_len, const uint8_t *msg, size_t msg_len, uint8_t out[16])`**
`hmac_lsh256()`과 동일하되 앞 16바이트만 `out`에 씀.

### 4.2 keymgmt/key_store.h

slave별·방향별(m2s/s2m/bc) 암호화 키와 MAC 키를 저장하는 테이블. `key_direction_t`: `DIR_MASTER_TO_SLAVE`, `DIR_SLAVE_TO_MASTER`, `DIR_BROADCAST`. `KEY_SIZE` = 16.

#### key_direction_index

```c
int key_direction_index(key_direction_t dir, int *out);
```
**매개변수**: `dir` [in] 방향 값. `out` [out] 0..2 테이블 인덱스.
**설명**: `key_direction_t`를 테이블 인덱스로 매핑. `key_store.c`와 `ctr_state.c`가 이 매핑을 공유(둘 다 (addr, dir) 테이블을 병렬로 색인하므로). 성공 시 0, `dir`이 잘못된 값이면 -1 반환.

#### key_store_lookup

```c
int key_store_lookup(uint8_t slave_addr, key_direction_t dir, directional_keys_t *out);
```
**매개변수**: `slave_addr` [in], `dir` [in], `out` [out] 암호화/MAC 키 쌍.
**설명**: 주어진 방향에서 `slave_addr`의 키 쌍을 조회. 성공 시 0, 등록되어 있지 않으면 -1 반환.

#### key_store_provision

```c
int key_store_provision(uint8_t slave_addr, key_direction_t dir, const directional_keys_t *keys);
```
**매개변수**: `slave_addr` [in], `dir` [in], `keys` [in].
**설명**: 주어진 방향에서 `slave_addr`의 키 쌍을 등록(또는 교체) — 커미셔닝/페어링 과정에서 한 번 호출. 성공 시 0, 실패 시 -1 반환.

#### key_store_load_file

```c
int key_store_load_file(const char *path);
```
**매개변수**: `path` [in] 키 파일 경로.
**설명**: `"<addr> <dir:m2s|s2m|bc> <enc_key:16자> <mac_key:16자> <initial_ctr:16진수 8자>"` 형식의 파일을 한 줄씩 읽어 테이블에 등록. `#` 주석 줄과 빈 줄은 건너뜀. 불러온 항목 수를 반환, 파일을 열 수 없으면 -1.

#### key_store_get_initial_ctr

```c
int key_store_get_initial_ctr(uint8_t slave_addr, key_direction_t dir, uint32_t *out);
```
**매개변수**: `slave_addr` [in], `dir` [in], `out` [out] `key_store_load_file()`이 읽은 초기 CTR 값.
**설명**: `ctr_state`가 그 (addr, dir)의 카운터를 처음 필요로 할 때 시드 값으로 사용. 성공 시 0, 미등록이면 -1.

### 4.3 keymgmt/ctr_state.h

slave별·방향별 CTR 카운터 상태 — 다음 송신 카운터, 지금까지 수신 허용된 최댓값, 재부팅 후에도 카운터 재사용을 막기 위한 영속화.

#### ctr_state_next_outgoing

```c
uint32_t ctr_state_next_outgoing(uint8_t slave_addr, key_direction_t dir, size_t msg_len);
```
**매개변수**: `slave_addr` [in], `dir` [in], `msg_len` [in] 이 카운터로 암호화될 평문 ADU 바이트 길이.
**설명**: 아직 사용되지 않은 다음 송신 카운터 값을 반환하고 저장된 카운터를 증가시킴. 새 메시지마다 정확히 한 번만 호출해야 함(재전송 시 다시 호출하면 안 됨). LEA-CTR은 16바이트 블록마다 카운터를 1씩 증가시키므로 `ceil(msg_len/16)`개의 연속 값이 이번 메시지에서 소비됨.

#### ctr_state_validate_incoming

```c
int ctr_state_validate_incoming(uint8_t slave_addr, key_direction_t dir, uint32_t ctr);
```
**매개변수**: `slave_addr` [in], `dir` [in], `ctr` [in] 수신된 카운터 값.
**설명**: `ctr < highest_accepted`면 거부(재전송 공격), `ctr == highest_accepted`면 허용(정상 재시도), `ctr > highest_accepted`면 허용 후 상한 갱신. 처리해야 하면 1, 거부해야 하면 0 반환. *(참고: 이 함수는 코드베이스 전체에서 선언·구현만 되어 있고 아직 호출되는 곳은 없음 — 재전송 방지가 필요해지면 사용할 API로 남아 있음.)*

#### ctr_state_persist / ctr_state_load

```c
int ctr_state_persist(void);
int ctr_state_load(void);
```
**설명**: 현재 카운터 상태를 비휘발성 저장소에 저장/불러옴. `ctr_state_next_outgoing()`을 호출할 때마다 즉시 기록하는 방식(배치 처리 없음). `ctr_state_load()`는 상태 파일이 없어도 실패로 취급하지 않음(-1 반환하되, 처음 필요해지는 시점에 `key_store`의 초기 CTR로 대체되므로 문제없음).

#### ctr_state_set_path

```c
void ctr_state_set_path(const char *path);
```
**설명**: `ctr_state_load()`/`ctr_state_persist()`가 기본값 `"ctr_state.dat"` 대신 사용할 파일 경로 지정.

#### ctr_state_reset

```c
void ctr_state_reset(uint8_t slave_addr, key_direction_t dir);
```
**매개변수**: `slave_addr` [in], `dir` [in].
**설명**: (slave_addr, dir)의 카운터 상태를 지워 처음 상태로 되돌림 — 다음 호출이 `key_store`의 initial_ctr부터 다시 시작. 재커미셔닝이나, 같은 프로세스 안에서 같은 (addr, dir)로 반복 테스트할 때(예: 셀프 테스트를 여러 번 실행) 이전 실행의 카운터 잔재로 어긋나는 것을 막는 데 사용 (§6.1 참고).

### 4.4 framing/secure_frame.h

#### secure_frame_build / secure_frame_parse

```c
size_t secure_frame_build(const secure_frame_t *frame, uint8_t *out);
int secure_frame_parse(const uint8_t *in, size_t len, secure_frame_t *frame);
```
**설명**: `frame`을 `[addr][ciphertext][hmac]` 형태로 `out`에 붙이거나(길이 반환), 반대로 `in`의 `len`바이트를 `frame`으로 파싱(성공 시 1, `len`이 addr+hmac을 담기에도 부족하면 0). HMAC 검증은 하지 않는 순수 구조 변환.

#### secure_frame_encrypt_and_build

```c
int secure_frame_encrypt_and_build(uint8_t slave_addr, const uint8_t *plaintext_pdu, size_t pdu_len,
                                    key_direction_t dir, uint8_t *out, size_t *out_len);
```
**매개변수**: `slave_addr` [in], `plaintext_pdu` [in] 함수코드+데이터, `pdu_len` [in], `dir` [in], `out` [out] 최소 `SECURE_FRAME_MAX_WIRE_LEN` 바이트, `out_len` [out].
**설명**: PDU 앞에 주소, 뒤에 표준 Modbus CRC16을 붙여 ADU로 만들고, (slave_addr, dir) 키로 조회해 송신 카운터로 LEA-CTR 암호화 후 HMAC-LSH256 계산, `[addr][ciphertext][hmac]`을 `out`에 저장. 성공 시 0, 키 조회 실패나 `pdu_len` 초과 시 -1.

#### secure_frame_verify_and_decrypt

```c
secure_frame_status_t secure_frame_verify_and_decrypt(
    const uint8_t *wire, size_t wire_len, uint8_t expected_addr, key_direction_t dir,
    uint8_t *out_addr, size_t *out_ciphertext_len,
    uint8_t *out_pdu, size_t *out_pdu_len,
    uint16_t *out_crc_calc, uint16_t *out_crc_recv);
```
**매개변수**: `wire`/`wire_len` [in] 수신 바이트, `expected_addr` [in] 주소 필터(`SECURE_FRAME_ANY_ADDR`이면 건너뜀), `dir` [in], `out_addr` [out] 파싱된 주소, `out_ciphertext_len`/`out_crc_calc`/`out_crc_recv` [out, 선택 — NULL 허용] 진단용 세부값, `out_pdu`/`out_pdu_len` [out] 복호화된 순수 PDU(최소 `SECURE_FRAME_MAX_PDU` 바이트).
**설명**: `secure_frame_encrypt_and_build()`의 역방향. 파싱 → (필요 시) 주소 검사 → 키 조회 → HMAC 검증 → LEA-CTR 복호화 → CRC16 검증 순으로 처리. `SECURE_FRAME_OK`(0)를 반환하면 `out_pdu`/`out_pdu_len`이 유효.

`secure_frame_status_t` 값:

| 값 | 의미 |
|---|---|
| `SECURE_FRAME_OK` (0) | 성공 |
| `SECURE_FRAME_ERR_MALFORMED` (-1) | addr+hmac을 담기에도 부족한 길이 |
| `SECURE_FRAME_ERR_WRONG_ADDR` (-2) | `expected_addr`을 지정했는데 `frame.addr`이 다름 |
| `SECURE_FRAME_ERR_NO_KEY` (-3) | `key_store`에 등록된 키 없음 |
| `SECURE_FRAME_ERR_HMAC` (-4) | HMAC 불일치 |
| `SECURE_FRAME_ERR_CRC` (-5) | 복호화 후 CRC16 불일치 (카운터 어긋남 의심) |

#### secure_frame_crc16

```c
uint16_t secure_frame_crc16(const uint8_t *buf, size_t len);
```
**설명**: 표준 Modbus CRC16(다항식 0xA001, 하위 바이트 먼저). `do_self_test()`류의 호출자가 `secure_frame_encrypt_and_build()`를 거치지 않고 직접 테스트 ADU를 구성할 때 필요해서 공개 함수로 노출.

### 4.5 modbus/modbus_pdu.h

지원 함수 코드 8종:

| 코드 | 이름 | 요청 PDU(함수코드 제외) | 응답 PDU(함수코드 제외) | `value_or_qty` 의미 |
|---|---|---|---|---|
| 0x01 | Read Coils | addr(2)+qty(2) | byte_count(1)+data | 읽을 개수 |
| 0x02 | Read Discrete Inputs | addr(2)+qty(2) | byte_count(1)+data | 읽을 개수 |
| 0x03 | Read Holding Registers | addr(2)+qty(2) | byte_count(1)+data(2×qty) | 읽을 개수 |
| 0x04 | Read Input Registers | addr(2)+qty(2) | byte_count(1)+data(2×qty) | 읽을 개수 |
| 0x05 | Write Single Coil | addr(2)+value(2, 0x0000/0xFF00) | 요청과 동일(반사) | 0=OFF, 0이 아니면 ON |
| 0x06 | Write Single Register | addr(2)+value(2) | 요청과 동일(반사) | 레지스터 값(0-65535) |
| 0x0F | Write Multiple Coils | addr(2)+qty(2)+byte_count(1)+data | addr(2)+qty(2) | 쓸 코일 개수 (값은 자동 생성) |
| 0x10 | Write Multiple Registers | addr(2)+qty(2)+byte_count(1)+data(2×qty) | addr(2)+qty(2) | 쓸 레지스터 개수 (값은 자동 생성) |

데모용 데이터 모델: `holding_registers`/`input_registers`/`coils`/`discrete_inputs` 각 128개(주소 0~127), 첫 사용 시 결정론적 패턴으로 초기화(`holding[i]=0x1000+i` 등)되어 실제 값처럼 보이는 데이터를 즉시 읽을 수 있음. quantity 상한(`MODBUS_MAX_READ_BITS`=2000, `MODBUS_MAX_WRITE_BITS`=1968, `MODBUS_MAX_READ_REGISTERS`=125, `MODBUS_MAX_WRITE_REGISTERS`=123)은 `libmodbus-master/src/modbus.h`와 동일한 값.

Modbus 예외 응답(`함수코드|0x80` + 예외코드):

| 예외 코드 | 이름 | 발생 조건 |
|---|---|---|
| 0x01 | Illegal Function | 함수 코드가 위 8종 밖 |
| 0x02 | Illegal Data Address | 주소(+수량)가 128개 데모 테이블 범위를 벗어남 |
| 0x03 | Illegal Data Value | 요청 길이가 그 함수 코드의 최소 필드보다 짧음 / quantity가 0이거나 프로토콜 상한 초과 / byte_count가 quantity와 안 맞음 / 코일 값이 0x0000·0xFF00이 아님 |

#### modbus_build_request

```c
int modbus_build_request(uint8_t func, uint16_t addr, uint16_t value_or_qty,
                          uint8_t *out_pdu, size_t *out_pdu_len);
```
**매개변수**: `func` [in] 위 8종 중 하나, `addr` [in] 시작 주소, `value_or_qty` [in] 함수 코드별 의미는 위 표 참고, `out_pdu` [out] 최소 `SECURE_FRAME_MAX_PDU` 바이트, `out_pdu_len` [out].
**설명**: 마스터가 요청 PDU를 만드는 함수. 여기서는 형식/quantity 상한만 검사하고 주소가 실제로 유효한지는 검사하지 않음(실제 마스터가 슬레이브의 정확한 레지스터 맵을 미리 안다고 가정하지 않는 것과 같은 이유) — 범위를 벗어나면 슬레이브가 `modbus_build_response()`에서 Illegal Data Address 예외로 정상 응답. 지원하지 않는 함수 코드이거나 quantity 상한을 초과하면 0, 성공 시 1 반환.

#### modbus_build_response

```c
int modbus_build_response(const uint8_t *req_pdu, size_t req_len,
                           uint8_t *resp_pdu, size_t *resp_len);
```
**매개변수**: `req_pdu`/`req_len` [in] `secure_frame_verify_and_decrypt()`가 돌려준 `out_pdu`/`out_pdu_len` 그대로, `resp_pdu` [out] 최소 `SECURE_FRAME_MAX_PDU` 바이트, `resp_len` [out].
**설명**: 슬레이브가 요청을 해석해 데이터 모델에 적용(쓰기)/조회(읽기)하고 응답 PDU를 만드는 함수. `req_len`이 0이면(함수 코드조차 없음) 회신 불가로 0 반환 — 호출자는 회신을 생략해야 함. 그 외에는 항상 1을 반환하며 `resp_pdu`에 정상 응답 또는 예외 응답이 담김(호출자는 어느 쪽인지 구분할 필요 없이 그대로 암호화해 보내면 됨).

### 4.6 demo/ 공용 유틸리티

| 함수 | 매개변수 | 설명 |
|---|---|---|
| `void exe_relative_path(const char *argv0, const char *filename, char *out, size_t out_size)` | argv0 [in], filename [in], out [out], out_size [in] | `"<argv0 디렉터리>/filename"` 문자열 조립. `keys.txt`/카운터 파일/로그 파일을 실행 파일 위치에 고정하는 데 사용 |
| `int demo_load_keys(const char *argv0)` | argv0 [in, NULL 허용] | `keys.txt`를 5가지 후보 경로로 순서대로 탐색해 로드 (cwd → 실행파일 옆 → `keymgmt/keys.txt` → `security/keymgmt/keys.txt` → `../keymgmt/keys.txt`). 불러온 항목 수(>0) 또는 실패 시 <=0 반환 |
| `long modbus_t35_us(long baud)` | baud [in] | Modbus RTU 스펙의 T3.5 유휴 간격을 마이크로초 단위로 계산 (실측 기반 20ms 최솟값 포함) |
| `void log_open(const char *path)` 외 `log_close_atexit`/`log_detail`/`log_summary`/`print_hex` | — | 파일 로깅 유틸리티 (`secure_send_demo`/`secure_recv_demo` 전용, §3 표 참고) |

---

## 5. 데모 프로그램 사용법

### 5.1 secure_demo (main.c) — 대화형 인터랙티브 도구

```
1. 마스터/슬레이브 모드 전환
2. 키 초기화
3. 단위 테스트
4. 환경 설정
5. 실행 (보안 통신 1회 수행)
6. 종료
```

- **1. 모드 전환**: `is_master` 플래그를 뒤집음.
- **2. 키 초기화**: `demo_load_keys()`로 `keys.txt` 로드.
- **3. 단위 테스트**: §6.1 참고.
- **4. 환경 설정**: 포트(빈 값=현재 유지, `-`=포트 없음/파일 폴백) → baud → slave 주소(마스터일 땐 보낼 대상, 슬레이브일 땐 자신의 주소) → 함수 코드(1/2/3/4/5/6/15/16 중 하나) → 시작 주소 → `value_or_qty`(함수 코드에 따라 라벨이 바뀜 — §4.5 표 참고).
- **5. 실행**: 마스터면 §4.5의 함수 코드로 요청을 만들어 암호화 후 전송(포트 미설정 시 `sent_frame.bin`에 기록). 슬레이브면 수신 프레임을 검증/복호화하고, 실제 포트가 있으면 응답까지 암호화해 회신(포트 없이 파일로 읽은 경우는 검증/복호화만).

### 5.2 secure_send_demo / secure_recv_demo — 배치 CLI 데모

```
secure_send_demo [port] [baud] [count]     # 포트 생략 시 sent_frame.bin에 기록
secure_recv_demo port [baud] [count]       # 포트 필수, 파일 폴백 없음
```

`secure_send_demo`는 함수 0x10(Write Multiple Registers) 프레임을 레지스터 1개~123개까지 크기를 늘려가며 `count`번 전송해 프레이밍을 모든 크기에서 스트레스 테스트한다(§4.5의 다른 함수 코드는 다루지 않음 — 의도적으로 이 도구의 범위 밖). `secure_recv_demo`는 실제 포트에서 프레임을 받아 검증/복호화하고 §4.5 로직으로 응답까지 회신한다.

---

## 6. 테스트 방법

### 6.1 셀프 테스트 (옵션 3, `do_self_test()`)

하드웨어 없이 한 프로세스 안에서 공개 API를 직접 호출해 검증하는 두 개의 체크로 구성:

- **encrypt-path 체크** (테스트 주소 `0xF0`, `DIR_MASTER_TO_SLAVE`): 실제 `secure_frame_encrypt_and_build()`를 호출한 뒤, 알고 있는 `ctr_low=0`으로 직접 HMAC/복호화/CRC를 검증.
- **decrypt-path 체크** (테스트 주소 `0xF1`, `DIR_SLAVE_TO_MASTER`): `ctr_low=0`으로 직접 만든 프레임을 실제 `secure_frame_verify_and_decrypt()`에 넘겨 검증. 파일 왕복 테스트(§6.2)로는 절대 닿지 않는 `DIR_SLAVE_TO_MASTER` 방향을 이 체크가 유일하게 커버함.

두 체크가 **서로 다른** 테스트 주소/방향을 쓰는 이유: `ctr_state`는 (addr, dir)별로 하나뿐인 프로세스 전역 카운터 테이블이라, 같은 (addr, dir)에 대해 encrypt 직후 decrypt를 또 실제 함수로 호출하면 내부 카운터가 이미 전진해 있어 복호화가 실패한다(재현 가능한 실제 버그였음 — `ctr_state_reset()`으로 고정, §4.3 참고). 서로 다른 (addr, dir) 슬롯을 쓰면 이 문제를 피할 수 있다.

실행: `secure_demo` 실행 후 `3` 입력. 기대 출력:
```
PASS (encrypt path): secure_frame_encrypt_and_build -> parse -> HMAC verify -> decrypt -> CRC check OK (5 byte PDU, 41 byte wire frame)
PASS (decrypt path): hand-built frame -> secure_frame_verify_and_decrypt OK (5 byte PDU, 41 byte wire frame)
Self-test: ALL PASS
```
같은 프로세스 안에서 여러 번 실행해도(옵션 3을 반복 선택) 매번 PASS해야 정상.

### 6.2 파일 왕복 테스트 (하드웨어 불필요)

포트를 설정하지 않은 상태에서:
1. 마스터로 `2`(키 초기화) → `4`(환경 설정, 원하는 함수 코드/주소/수량 입력) → `5`(실행) — `sent_frame.bin`에 씀.
2. 새 프로세스(또는 `1`로 모드 전환)에서 `2` → `5`(실행) — `sent_frame.bin`을 읽어 검증/복호화. `Recovered PDU`가 §4.5 표대로 나오는지 확인.

**한계**: 포트가 없으면(`sp == NULL`) 슬레이브가 응답을 만들지 않으므로, 이 방법은 요청 방향(`DIR_MASTER_TO_SLAVE`)의 PDU 인코딩만 검증한다. 응답 생성(`modbus_build_response()`)은 이 방법으로 닿지 않으므로 §6.3으로 검증.

### 6.3 modbus_pdu 단위 테스트 하네스

`modbus_build_response()`는 실제 포트가 있을 때만 호출되므로(§6.2의 한계), 이 함수만 따로 떼어 직접 호출하는 독립 테스트 프로그램으로 검증한다 — `secure_frame`/`ctr_state`/시리얼 포트 어느 것도 필요 없는 순수 함수이므로 가능하다.

```c
/* test_modbus_response.c 예시 골자 */
#include "modbus_pdu.h"
uint8_t resp[300]; size_t resp_len;
uint8_t req[] = {0x03, 0x00, 0x00, 0x00, 0x02}; /* Read Holding Registers, addr 0, qty 2 */
int rc = modbus_build_response(req, sizeof(req), resp, &resp_len);
/* rc==1, resp == {0x03, 0x04, 0x10, 0x00, 0x10, 0x01} 확인 */
```

```bash
gcc -Wall -Wextra -I modbus test_modbus_response.c modbus/modbus_pdu.c -o test_modbus_response
./test_modbus_response
```

검증해야 할 것: §4.5의 8개 함수 코드 성공 경로(쓰기 함수는 쓰기 직후 읽기로 반영 확인), 3가지 예외 코드(Illegal Function/Data Address/Data Value 각각을 유발하는 입력), 그리고 경계 조건(길이 0 요청 → 회신 없음, 함수 코드는 있지만 나머지가 짧은 요청 → 조용히 버리지 않고 예외로 응답).

### 6.4 실제 장비(Pi) 검증 절차

라이브 배포본을 건드리지 않고 실제 aarch64/NEON 타겟에서 검증하려면 별도 스크래치 디렉터리에 소스를 복사해 빌드한다:

```bash
ssh <host> "mkdir -p ~/security_test"
git archive <branch-or-main> | ssh <host> "tar -x -C ~/security_test"
scp keymgmt/keys.txt <host>:~/security_test/keymgmt/keys.txt   # keys.txt는 .gitignore 대상이라 git archive에 안 들어감
ssh <host> "cd ~/security_test && make clean && make all"
ssh <host> "cd ~/security_test && printf '2\n3\n6\n' | ./secure_demo"   # 셀프 테스트
```
확인 후: `ssh <host> "rm -rf ~/security_test"`로 정리.

### 6.5 회귀 체크리스트

- [ ] 셀프 테스트(옵션 3) 여러 번 연속 실행 시 매번 `ALL PASS`
- [ ] 슬레이브 주소를 프레임과 다르게 설정하면 `Frame addressed to slave X, not us (configured as Y) -- ignoring`로 무시됨
- [ ] §4.5의 8개 함수 코드 모두 `환경 설정` → `실행`으로 요청 PDU가 표대로 만들어짐 (§6.2)
- [ ] `modbus_pdu` 하네스(§6.3)에서 8개 함수 코드 성공 경로 + 3개 예외 코드 + 경계 조건 전부 PASS
- [ ] Pi에서 위 항목들을 다시 실행해도 동일하게 PASS (§6.4)
