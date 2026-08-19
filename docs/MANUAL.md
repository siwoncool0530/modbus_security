# security 소스코드 사용 매뉴얼

LEA-CTR 암호화와 LSH-HMAC 해시를 통한 MODBUS 프레임 종단간 암호화 프로그램 사용 매뉴얼 (2026.08)

## 차례

1. [개요](#1-개요)
2. [소스코드 구성](#2-소스코드-구성)
3. [빌드 방법](#3-빌드-방법)
4. [인터페이스](#4-인터페이스)
   - 4.1 [crypto/](#41-crypto)
   - 4.2 [keymgmt/key_store.h](#42-keymgmtkey_storeh)
   - 4.3 [keymgmt/ctr_state.h](#43-keymgmtctr_stateh)
   - 4.4 [framing/secure_frame.h](#44-framingsecure_frameh)
   - 4.5 [modbus/modbus_pdu.h](#45-modbusmodbus_pduh)
   - 4.6 [demo/ 공용 유틸리티](#46-demo-공용-유틸리티)
5. [데모 프로그램 사용법](#5-데모-프로그램-사용법)
6. [테스트 방법](#6-테스트-방법)
7. [참조 문헌](#7-참조-문헌)

---

## 1. 개요

`security/`는 Modbus RTU 통신에 기밀성(암호화)과 무결성/인증(HMAC)을 더하는 보안 래퍼로, LEA-CTR 암호화와 HMAC-LSH256 인증을 사용한다. LEA와 LSH 알고리즘 자체의 상세 규격/구현은 별도의 공식 매뉴얼(`블록암호 LEA 소스코드 사용 매뉴얼`, `해시함수 LSH 소스코드 사용 매뉴얼`)에 문서화되어 있으므로, 이 문서는 그 위에 이 프로젝트가 직접 구현한 계층만 다룬다.

### 계층 구조

```plaintext
crypto/    LEA, LSH/HMAC 원시 함수 (얇은 래퍼만 이 문서에서 다룸, §4.1)
keymgmt/   키 테이블 + 방향별(m2s/s2m/bc) CTR 카운터 상태
framing/   [addr|ciphertext|hmac] 와이어 프레임 구조 -- 내용물(PDU)이 뭔지는 모름
modbus/    PDU 내용물 (함수 코드, 코일/레지스터 데이터 모델, 예외 응답) -- 암호화는 전혀 모름
demo/      위 계층들을 엮은 실행 가능한 도구 (인터랙티브 도구 + 두 개의 배치 데모)
```

각 계층은 자신의 바로 아래 계층만 알고, 위 계층은 전혀 모른다. 예를 들어 `framing/`은 PDU 안에 Modbus 함수 코드가 들어있다는 사실 자체를 모르고, `modbus/`는 그 PDU가 암호화되어 전송된다는 사실을 모른다.

### 와이어 프레임 구조

```plaintext
[addr(1)][ciphertext = LEA-CTR(addr + PDU + CRC16)][hmac(32)]
```

- `addr`: 평문으로 한 번 더 앞에 붙음 - 복호화 전에 프레임을 라우팅해야 하므로 필요.
- `ciphertext`: Modbus ADU(주소+PDU+CRC16) 전체를 LEA-CTR로 암호화한 암호문. CTR 카운터 자체는 전송되지 않고 송수신측 양쪽이 `keymgmt/ctr_state.h`로 각자 추적.
- `hmac`: `addr || ciphertext`에 대한 HMAC-LSH256 (32바이트).

### 설계 근거

**왜 CTR 카운터를 전송하지 않는가.** 키 관리 서버에서 안전하게 받아온다고 가정. 코드에서는 마스터와 슬레이브가 각자 독립적으로 카운터를 증가시키며 같은 순서로 프레임을 처리한다고 약속함. **프레임 하나라도 유실되면 두 쪽의 카운터가 어긋남 주의** — `ctr_state_reset()`(§4.3)이 그 상황을 복구.

**왜 (해시가 아니라) HMAC인가.** `hmac_lsh256()`은 암호 키가 들어간 구성. 평문 해시는 아무나 계산할 수 있으므로 "이 프레임이 변조되지 않았다"만 보장하고 "이 프레임을 우리가 공유한 키를 가진 쪽이 만들었다"는 보장하지 못하므로 보안 취약점 해소 위해 HMAC 사용.

**왜 CRC16을 암호문 안에도 두는가.** `secure_frame_verify_and_decrypt()`가 HMAC 검증에 성공한 뒤 복호화하고 CRC를 다시 확인하는데, 이 CRC 검증은 카운터가 어긋났을 때의 1차 진단 신호로 확인(§4.4, `SECURE_FRAME_ERR_CRC`) — HMAC은 키가 맞는 발신자가 보냈다는 것만 보장하고, 복호화에 쓴 카운터가 송신 측과 일치했는지는 보장하지 않으므로, CRC가 그 어긋남을 잡아내는 역할을 겸한다.

### 보안 상 제약사항

- **재전송(replay) 방지 미적용**: `ctr_state_validate_incoming()`(§4.3)이 재전송 탐지 로직을 구현하고 있지만, 코드 전체에서 실제로 호출되는 곳이 없다. 현재 수신측은 "다음에 올 프레임은 다음 카운터를 쓸 것"이라 가정하고 복호화 시도. 실제 환경에서는 재전송 시 탐지 로직이 필요하다.
- **HMAC 비교가 상수 시간이 아님**: `secure_frame.c`가 `memcmp()`로 HMAC을 비교해 시간복잡도 O(N).
- **카운터 손실 가능**: `ctr_state_persist()`는 매 호출마다 파일을 단순 재작성(임시파일에 쓰고 rename하는 방식이 아님). 기록 도중 전원이 끊기면 카운터 파일이 손상될 수 있어 실제 트래픽 처리 전에 재검토 필요.
- **`modbus/`의 데이터 모델은 데모용**: 코일/레지스터 128개 고정 크기 배열이며 실제 슬레이브 장비의 레지스터 맵을 반영하지 않는다.

---

## 2. 소스코드 구성

### crypto/ (LEA, LSH 원본 및 참조 함수)

| 파일명 | 내용 |
| --- | --- |
| `lea.h`/`lea.c` | LEA 키 스케줄 생성 (`lea_key_schedule`) |
| `lea_ctr.h`/`lea_ctr.c` | LEA-CTR 암/복호화 담당 |
| `hmac_lsh.h`/`hmac_lsh.c` | HMAC-LSH256 담당 |
| `lea_ref/` | LEA 라이브러리 |
| `lsh_ref/` | LSH/HMAC 라이브러리 |

### keymgmt/ — 키 테이블과 카운터 상태

| 파일명 | 내용 |
| --- | --- |
| `key_store.h`/`key_store.c` | slave별/방향별 암호화·MAC 키 테이블, `keys.txt` 로더 |
| `ctr_state.h`/`ctr_state.c` | slave별/방향별 CTR 카운터 상태 관리 |
| `keys.txt` | 테스트용 키 소스 파일 |

### framing/ — 프레임 생성

| 파일명 | 내용 |
| --- | --- |
| `secure_frame.h`/`secure_frame.c` | `[addr\|ciphertext\|hmac]` 프레임 조립/파싱, 암호화+HMAC 결합(`encrypt_and_build`), 복호화+HMAC 검증 결합(`verify_and_decrypt`) |

### modbus/ — Modbus PDU 로직

| 파일명 | 내용 |
| --- | --- |
| `modbus_pdu.h`/`modbus_pdu.c` | 함수 코드 8종의 요청/응답 PDU 조립, 데모용 코일/레지스터 데이터 모델, Modbus 예외 응답 |
| `modbus_pdu_selftest.h`/`modbus_pdu_selftest.c` | 요청 PDU 기반 응답(정상/예외 응답) PDU 정상 생성 여부를 검증하는 자체 테스트 (§6.1에서 `secure_demo` 옵션 3이 호출) |

### demo/ — 실행 가능한 도구와 공용 유틸리티

| 파일명 | 내용 |
| --- | --- |
| `main.c` | 프로토타입(`secure_demo`) -- 마스터/슬레이브 모드, 키 초기화, 셀프 테스트, 환경 설정, 실행 |
| `secure_send_demo.c` | 프레임 송신 데모(`secure_send_demo`) -- 1~123개의 레지스터로 프레임 크기를 달리하여 프레이밍 스트레스 테스트 |
| `secure_recv_demo.c` | 프레임 수신 데모(`secure_recv_demo`) -- 실제 하드웨어로 왕복 검증 |
| `serial_port.h`/`serial_port.c` | COM/tty 포트 열기/읽기/쓰기, Modbus T3.5 유휴 간격 계산(`modbus_t35_us`) |
| `key_paths.h`/`key_paths.c` | 실행 파일 상대 경로 계산, `keys.txt` 탐색 |
| `demo_log.h`/`demo_log.c` | 파일 로깅 유틸리티 |
| `rs485_probe.c` | 커널 RS-485 드라이버 지원 여부 확인용 |

---

## 3. 빌드 방법

### Makefile 대상

```bash
make            # secure_send_demo, secure_recv_demo, secure_demo 세 개 모두 빌드
make clean      # 빌드 산출물 정리
make NO_NEON=1  # NEON 대신 일반 C 경로로 빌드
```

### 아키텍처 자동 감지 (`ARCH := $(shell uname -m)`)

| ARCH | LEA SIMD 백엔드 | 비고 |
| --- | --- | --- |
| `aarch64` | NEON (`NO_NEON=1`이면 일반 C) | 실제 타겟(Raspberry Pi 5 / CM5) |
| `armv7l` | NEON (`NO_NEON=1`이면 일반 C) | |
| 그 외(x86_64 등) | 일반 C만 (SIMD 없음) | Windows 등에서 개발용 빌드 |

### `make`가 없는 환경의 수동 빌드

```bash
gcc -O2 -Wall -DNO_AVX2 -DNO_XOP -DNO_PCLMUL -DNO_SSE2 \
  demo/main.c \
  framing/secure_frame.c keymgmt/key_store.c keymgmt/ctr_state.c \
  crypto/lea.c crypto/lea_ctr.c crypto/hmac_lsh.c \
  crypto/lsh_ref/src/lsh.c crypto/lsh_ref/src/lsh256.c crypto/lsh_ref/src/lsh512.c crypto/lsh_ref/src/hmac.c \
  crypto/lea_ref/lea_base.c crypto/lea_ref/lea_core.c crypto/lea_ref/lea_online.c \
  crypto/lea_ref/lea_gcm_generic.c crypto/lea_ref/lea_t_fallback.c crypto/lea_ref/lea_t_generic.c \
  crypto/lea_ref/cpu_info_ia32.c \
  demo/serial_port.c demo/key_paths.c modbus/modbus_pdu.c modbus/modbus_pdu_selftest.c \
  -o secure_demo.exe -lws2_32
```

`secure_send_demo`/`secure_recv_demo`를 만들 때는 `demo/main.c`를 `demo/secure_send_demo.c`(또는 `secure_recv_demo.c`)로 바꾸고 `demo/demo_log.c`를 추가한다. `secure_recv_demo`는 `modbus/modbus_pdu.c`도 필요하지만 `secure_send_demo`는 필요 없다(아래 표 참고).

### 실행 파일별 필요 오브젝트

세 실행 파일은 공통 오브젝트(`$(LIB_OBJS)`: `framing/`+`keymgmt/`+`crypto/`+`demo/serial_port.c`+`demo/key_paths.c`)를 공유:

| 실행 파일 | `$(LIB_OBJS)` | `demo_log.o` | `modbus_pdu.o` |
| --- | :---: | :---: | :---: |
| `secure_demo` (main.c) | ✅ | ❌ (`print_hex` 사용) | ✅ (마스터=요청 생성, 슬레이브=응답 생성) |
| `secure_send_demo` | ✅ | ✅ | ❌ (슬레이브 역할 없음, 고정 함수 0x10 스윕만 함) |
| `secure_recv_demo` | ✅ | ✅ | ✅ (슬레이브=응답 생성) |

---

## 4. 인터페이스

### 4.1 crypto/

LEA/LSH의 호출부 입출력만 기록. 이 세 함수는 모두 입력값이 정해진 길이/형식만 맞으면 실패하지 않는 순수 계산 함수라 반환값이 없고(void), 별도의 예외/경계 조건도 없다.

**`void lea_key_schedule(const uint8_t key[16], lea_key_schedule_t *ks)`**\
입력: `key` 16바이트 LEA-128 마스터키 (다른 길이는 지원하지 않음, 이 프로젝트는 항상 128비트 키만 씀).\
출력: `ks` 에 라운드 키 채움. 기본값 없음 (매 호출 시 반드시 실제 키를 넘겨야 함).

```c
uint8_t enc_key[16] = { 0x01, 0x02, /* ... */ };
lea_key_schedule_t ks;
lea_key_schedule(enc_key, &ks);
// 이후 lea_ctr_crypt(&ks, ...)로 암/복호화 
```

**`void hmac_lsh256(const uint8_t *key, size_t key_len, const uint8_t *msg, size_t msg_len, uint8_t out[32])`**\
입력: `key`/`key_len` MAC 키, `msg`/`msg_len` 메시지.\
출력: `out` 에 32바이트(`HMAC_LSH_FULL_SIZE`) HMAC-LSH256 값을 담음.

```c
uint8_t mac_key[16] = { /* ... */ };
uint8_t tag[HMAC_LSH_FULL_SIZE];
hmac_lsh256(mac_key, KEY_SIZE, wire_frame, wire_frame_len, tag);
```

### 4.2 keymgmt/key_store.h

slave별 · 방향별(master to slave; m2s / slave to master; s2m / broadcast; bc) 암호화 키와 MAC 키를 저장하는 테이블(프로세스 전역, `static` 배열). `key_direction_t`: `DIR_MASTER_TO_SLAVE`, `DIR_SLAVE_TO_MASTER`, `DIR_BROADCAST`. `KEY_SIZE` = 16(고정값, 변경 불가). 슬레이브 주소 유효 범위는 0~247(`KEY_STORE_MAX_ADDR`, Modbus 주소 체계와 동일) — 이 범위를 넘는 `slave_addr`은 모든 함수에서 -1로 예외처리.

#### key_direction_index

```c
int key_direction_index(key_direction_t dir, int *out);
```

**매개변수**: `dir` [in] 방향 값(기본값 없음 — 항상 명시). `out` [out] 0..2 테이블 인덱스.\
**설명**: `key_direction_t`를 테이블 인덱스로 매핑. `key_store.c`와 `ctr_state.c`가 이 매핑을 공유(둘 다 (addr, dir) 테이블을 병렬로 색인하므로). 성공 시 0, `dir`이 세 값 중 하나가 아니면 -1 반환.\
**동작/경계 조건**: 이 함수는 다른 모든 `key_store_*`/`ctr_state_*` 함수 내부에서 호출되므로, 잘못된 `key_direction_t` 값(예: 정수를 강제 캐스팅해 3 이상을 넘긴 경우)을 넘기면 그 상위 함수들도 전부 예외 반환(-1 또는 0).

#### key_store_lookup

```c
int key_store_lookup(uint8_t slave_addr, key_direction_t dir, directional_keys_t *out);
```

**매개변수**: `slave_addr` [in] 0~247, `dir` [in], `out` [out] 암호화/MAC 키 쌍.\
**설명**: 주어진 방향에서 `slave_addr`의 키 쌍을 조회. 성공 시 0, 등록되어 있지 않으면 -1 반환.\
**동작/경계 조건**: 프로세스 시작 직후(아무것도 `provision`/`load_file`하지 않은 상태)에는 모든 (addr, dir) 조합이 미등록 상태라 항상 -1이 반환된다. `framing/secure_frame.c`는 이 -1을 `SECURE_FRAME_ERR_NO_KEY`로 변환해 호출자에게 전달한다.

```c
directional_keys_t keys;
if (key_store_lookup(1, DIR_MASTER_TO_SLAVE, &keys) == 0) {
    /* keys.enc_key, keys.mac_key 사용 가능 */
} else {
    printf("slave 1의 m2s 키가 등록되어 있지 않음\n");
}
```

#### key_store_provision

```c
int key_store_provision(uint8_t slave_addr, key_direction_t dir, const directional_keys_t *keys);
```

**매개변수**: `slave_addr` [in], `dir` [in], `keys` [in].\
**설명**: 주어진 방향에서 `slave_addr`의 키 쌍을 등록(또는 교체). 성공 시 0, `slave_addr`이 247을 넘거나 `dir`이 잘못된 값이면 -1 반환.\
**동작/경계 조건**: **이미 등록된 (addr, dir)에 다시 호출하면 키뿐만 아니라 `initial_ctr`도 무조건 0으로 리셋됨.** `key_store_load_file()`로 파일에서 읽어온 `initial_ctr`이 있어도 그 뒤에 `key_store_provision()`을 호출하면 덮어써진다. 순서를 바꿔 부르면(먼저 provision, 나중에 load_file) 파일의 `initial_ctr` 값이 최종적으로 남는다.

```c
directional_keys_t dk;
memcpy(dk.enc_key, my_16_byte_key, KEY_SIZE);
memcpy(dk.mac_key, my_16_byte_mac_key, KEY_SIZE);
key_store_provision(1, DIR_MASTER_TO_SLAVE, &dk); /* initial_ctr은 0으로 설정됨 */
```

#### key_store_load_file

```c
int key_store_load_file(const char *path);
```

**매개변수**: `path` [in] 키 파일 경로. 기본 파일명은 호출자가 정함(이 프로젝트의 데모들은 `"keys.txt"`를 관례로 씀).\
**설명**: `"<addr> <dir:m2s|s2m|bc> <enc_key:16자> <mac_key:16자> <initial_ctr:16진수 8자>"` 형식의 파일을 한 줄씩 읽어 테이블에 등록. `#`로 시작하는 줄과 빈 줄은 건너뜀. 불러온 항목 수를 반환, 파일을 열 수 없으면 -1.\
**동작/경계 조건**: 형식이 안 맞는 줄(필드 개수가 5개가 아님, `enc_key`/`mac_key` 길이가 정확히 16자가 아님, `addr`이 247 초과, `dir` 토큰이 `m2s`/`s2m`/`bc`가 아님)은 **에러 없이 건너뛴다** — 반환값은 오직 "성공적으로 파싱해 등록한 키의 수"이므로, 파일에 오타가 있어도 프로그램은 그냥 그 줄을 무시하고 계속 진행한다. 파일 전체가 형식에 맞지 않으면 유효한 키가 없으므로 반환값 0(`demo_load_keys()`는 0 이하를 실패로 취급).

```c
int loaded = key_store_load_file("keys.txt");
if (loaded <= 0) {
    printf("키를 하나도 불러오지 못함\n");
}
```

#### key_store_get_initial_ctr

```c
int key_store_get_initial_ctr(uint8_t slave_addr, key_direction_t dir, uint32_t *out);
```

**매개변수**: `slave_addr` [in], `dir` [in], `out` [out] `key_store_load_file()`이 읽은 초기 CTR 값(16진수 8자를 `uint32_t`로 파싱한 값). 기본값: `key_store_provision()`만으로 등록된 항목은 항상 0(위 참고).\
**설명**: `ctr_state`가 그 (addr, dir)의 카운터를 처음 필요로 할 때 시드 값으로 사용. 성공 시 0, 미등록이면 -1. 이 함수를 직접 호출할 일은 거의 없고, `ctr_state_next_outgoing()`/`ctr_state_validate_incoming()`이 내부적으로 호출.

### 4.3 keymgmt/ctr_state.h

slave별·방향별 CTR 카운터 상태 테이블(다음 송신 시 사용할 카운터, 지금까지 수신된 카운터 최댓값). 이 테이블도 `key_store`처럼 프로세스 전역이며 기본값은 "미설정"(첫 호출 시 `key_store_get_initial_ctr()`로 시드).

#### ctr_state_next_outgoing

```c
uint32_t ctr_state_next_outgoing(uint8_t slave_addr, key_direction_t dir, size_t msg_len);
```

**매개변수**: `slave_addr` [in], `dir` [in], `msg_len` [in] 이 카운터로 암호화될 평문 ADU 바이트 길이(0도 허용 — 아래 참고).\
**설명**: 아직 사용되지 않은 다음 송신 카운터 값을 반환하고 저장된 카운터를 증가시킴. LEA-CTR은 16바이트 블록마다 카운터를 1씩 증가시키므로 `ceil(msg_len/16)`개의 연속 값이 이번 메시지에서 소비됨(`msg_len == 0`이어도 최소 1블록은 예약됨).\
**동작/경계 조건**: **새 메시지마다 정확히 한 번만 호출해야 한다.** 같은 (addr, dir)에 대해 의도치 않게 두 번 연달아 호출하면(예: 암호화 함수 안에서 한 번 소비된 뒤, 그 결과를 복호화하려고 또 호출) 두 번째 호출은 다음 메시지용 카운터를 돌려주므로 복호화가 실패. `secure_frame.c`가 encrypt와 decrypt 경로에서 각각 정확히 한 번씩만 이 함수를 호출하도록 설계. `slave_addr`이 247을 넘거나 `dir`이 잘못된 값이면 0을 반환(에러 코드가 아니라 유효한 첫 카운터 값과 구분이 안 되므로 호출 전에 입력을 스스로 검증해야 함).

#### ctr_state_validate_incoming

```c
int ctr_state_validate_incoming(uint8_t slave_addr, key_direction_t dir, uint32_t ctr);
```

**매개변수**: `slave_addr` [in], `dir` [in], `ctr` [in] 수신된 카운터 값.\
**설명**: `ctr < highest_accepted`면 거부(재전송 공격), `ctr == highest_accepted`면 허용(정상 재시도 — 호출자는 새 메시지로 취급하지 말고 재처리해야 함), `ctr > highest_accepted`면 허용 후 상한 갱신. 처리해야 하면 1, 거부해야 하면 0 반환.\
**동작/경계 조건**: 이 함수는 코드베이스 전체에서 선언·구현만 되어 있고 아직 실제로 호출되는 곳이 없음. — 재전송 방지가 필요해지면 사용할 API. 지금은 `secure_frame_verify_and_decrypt()`가 이 함수 대신 `ctr_state_next_outgoing()`으로 카운터를 재구성해 복호화만 시도할 뿐, 수신한 카운터가 실제로 유효한 범위인지는 검증하지 않는다.

#### ctr_state_persist / ctr_state_load

```c
int ctr_state_persist(void);
int ctr_state_load(void);
```

**설명**: 현재 카운터 상태를 비휘발성 저장소에 저장/불러옴. `ctr_state_next_outgoing()`을 호출할 때마다 즉시 기록. `ctr_state_load()`는 상태 파일이 없어도 실패로 취급하지 않음(-1 반환하되, 처음 필요해지는 시점에 `key_store`의 초기 CTR로 대체되므로 문제없음). 기본 파일 경로: `"ctr_state.dat"` (아래 `ctr_state_set_path()` 참고).

#### ctr_state_set_path

```c
void ctr_state_set_path(const char *path);
```

**매개변수**: `path` [in] 상태 파일 경로. **기본값**: `"ctr_state.dat"` (헤더의 `CTR_STATE_DEFAULT_PATH`).\
**설명**: `ctr_state_load()`/`ctr_state_persist()`가 기본값 대신 사용할 파일 경로 지정. 이 프로젝트의 `main.c`는 마스터일 땐 `"ctr_state.dat"`, 슬레이브일 땐 `"ctr_state_recv.dat"`로 나눠 쓴다(한 프로세스에서 모드를 오갈 때 카운터가 섞이지 않도록).

```c
ctr_state_set_path("ctr_state_recv.dat");
ctr_state_load(); // 실패해도 무방 -- 첫 사용 시 key_store의 initial_ctr로 대체됨
```

#### ctr_state_reset

```c
void ctr_state_reset(uint8_t slave_addr, key_direction_t dir);
```

**매개변수**: `slave_addr` [in], `dir` [in].\
**설명**: (slave_addr, dir)의 카운터 상태를 지워 처음 상태로 되돌려 다음 호출이 `key_store`의 initial_ctr부터 다시 시작. 같은 프로세스 안에서 같은 (addr, dir)로 반복 테스트할 때(예: 셀프 테스트를 여러 번 실행) 이전 실행의 카운터 잔재로 어긋나는 것을 막는 데 사용 (§6.1 참고). 호출 즉시 `ctr_state_persist()`도 함께 실행되므로 파일에도 리셋된 상태가 반영된다.

### 4.4 framing/secure_frame.h

#### secure_frame_build / secure_frame_parse

```c
size_t secure_frame_build(const secure_frame_t *frame, uint8_t *out);
int secure_frame_parse(const uint8_t *in, size_t len, secure_frame_t *frame);
```

**매개변수**: `frame` [in, `secure_frame_build`] / [out, `secure_frame_parse`], `out`/`in` [out]/[in] 바이트 버퍼, `len` [in].\
**설명**: `frame`을 `[addr][ciphertext][hmac]` 형태로 `out`에 붙이거나(길이 반환), 반대로 `in`의 `len`바이트를 `frame`으로 파싱(성공 시 1, `len`이 addr+hmac을 담기에도 부족하면 0).\ **HMAC 검증은 하지 않는 순수 구조 변환** — 신뢰할 수 없는 입력(네트워크/시리얼에서 막 받은 바이트)에는 이 함수만 단독으로 쓰지 말고 `secure_frame_verify_and_decrypt()`를 쓸 것.

#### secure_frame_encrypt_and_build

```c
int secure_frame_encrypt_and_build(uint8_t slave_addr, const uint8_t *plaintext_pdu, size_t pdu_len,
                                    key_direction_t dir, uint8_t *out, size_t *out_len);
```

**매개변수**: `slave_addr` [in], `plaintext_pdu` [in] 함수코드+데이터, `pdu_len` [in] 최대 `SECURE_FRAME_MAX_PDU`(253)바이트, `dir` [in], `out` [out] 호출자가 최소 `SECURE_FRAME_MAX_WIRE_LEN`(288)바이트로 준비해야 함, `out_len` [out].\
**설명**: PDU 앞에 주소, 뒤에 표준 Modbus CRC16을 붙여 ADU로 만들고, (slave_addr, dir) 키로 조회해 송신 카운터로 LEA-CTR 암호화 후 HMAC-LSH256 계산, `[addr][ciphertext][hmac]`을 `out`에 저장. 성공 시 0, `key_store_lookup()` 실패나 `pdu_len > SECURE_FRAME_MAX_PDU` 시 -1.\
**동작/경계 조건**: 내부적으로 `ctr_state_next_outgoing(slave_addr, dir, adu_len)`을 **정확히 한 번** 호출한다 — 이 함수를 호출할 때마다 그 (addr, dir)의 카운터가 실제로 전진하므로, 같은 프레임을 다시 만들어서 재전송하면 안 된다(재전송하려면 이미 만들어진 `out` 바이트를 그대로 다시 보내야 함, 이 함수를 또 호출하면 안 됨).

```c
uint8_t wire[SECURE_FRAME_MAX_WIRE_LEN];
size_t wire_len;
uint8_t pdu[] = {0x03, 0x00, 0x00, 0x00, 0x02}; /* Read Holding Registers, addr 0, qty 2 */

if (secure_frame_encrypt_and_build(1, pdu, sizeof(pdu), DIR_MASTER_TO_SLAVE, wire, &wire_len) != 0) {
    printf("slave 1의 m2s 키가 없음\n");
} else {
    serial_port_write(&sp, wire, wire_len);
}
```

#### secure_frame_verify_and_decrypt

```c
secure_frame_status_t secure_frame_verify_and_decrypt(
    const uint8_t *wire, size_t wire_len, uint8_t expected_addr, key_direction_t dir,
    uint8_t *out_addr, size_t *out_ciphertext_len,
    uint8_t *out_pdu, size_t *out_pdu_len,
    uint16_t *out_crc_calc, uint16_t *out_crc_recv);
```

**매개변수**: `wire`/`wire_len` [in] 수신 바이트, `expected_addr` [in] 주소 필터(**기본값 성격의 값 `SECURE_FRAME_ANY_ADDR`(0xFF)을 넘기면 필터를 건너뜀** — RS-485처럼 여러 슬레이브가 한 버스에 있을 때만 실제 주소를 넘기고, 그 외엔 이 값을 쓰면 됨), `dir` [in], `out_addr` [out] 파싱된 주소(파싱에 성공하면 상태 코드와 무관하게 항상 채워짐), `out_ciphertext_len`/`out_crc_calc`/`out_crc_recv` [out, 선택 — NULL 허용] 진단 메시지용 세부값, `out_pdu`/`out_pdu_len` [out] 복호화된 순수 PDU(호출자가 최소 `SECURE_FRAME_MAX_PDU`(253)바이트로 준비).\
**설명**: `secure_frame_encrypt_and_build()`의 역방향. 파싱 → (필요 시) 주소 검사 → 키 조회 → HMAC 검증 → LEA-CTR 복호화 → CRC16 검증 순으로 처리. `SECURE_FRAME_OK`(0)를 반환하면 `out_pdu`/`out_pdu_len`이 유효.\
**동작/경계 조건**:

- HMAC 비교는 `memcmp()`로 이루어짐 — 상수 시간 비교가 아니므로 §1의 "보안 상 제약사항" 참고.
- `SECURE_FRAME_ERR_CRC`는 대개 "HMAC은 맞는데 복호화 결과가 깨짐" = **카운터가 어긋났다는 신호** — 키가 틀렸다면 HMAC 단계에서 먼저 걸러지므로, CRC까지 통과 못 했다는 건 인증은 됐지만 잘못된 카운터로 복호화했다는 뜻.
- 내부적으로 `ctr_state_next_outgoing()`을 호출하므로(§4.3 참고), **같은 (addr, dir)로 이 함수를 두 번 연달아 부르면 두 번째 호출은 실패한다** — `secure_frame_encrypt_and_build()`로 막 만든 프레임을 같은 프로세스에서 바로 이 함수로 복호화해보는 건 안 된다(§6.1 단위 테스트가 이 문제를 피해가는 방법을 그대로 보여줌).

```c
uint8_t addr, pdu[SECURE_FRAME_MAX_PDU];
size_t ciphertext_len, pdu_len;
uint16_t crc_calc, crc_recv;

secure_frame_status_t st = secure_frame_verify_and_decrypt(
    rx_buf, rx_len, SECURE_FRAME_ANY_ADDR, DIR_MASTER_TO_SLAVE,
    &addr, &ciphertext_len, pdu, &pdu_len, &crc_calc, &crc_recv);

switch (st) {
case SECURE_FRAME_OK:
    /* pdu[0..pdu_len) 사용 */
    break;
case SECURE_FRAME_ERR_CRC:
    printf("CRC 불일치 (calc %04X, recv %04X) -- 카운터 어긋남?\n", crc_calc, crc_recv);
    break;
default:
    printf("검증 실패: status=%d\n", (int) st);
}
```

`secure_frame_status_t` 값:

| 값 | 의미 |
| --- | --- |
| `SECURE_FRAME_OK` (0) | 성공 |
| `SECURE_FRAME_ERR_MALFORMED` (-1) | addr+hmac을 담기에도 부족한 길이 - `out_addr` 등은 채워지지 않음 |
| `SECURE_FRAME_ERR_WRONG_ADDR` (-2) | `expected_addr`을 지정했는데 `frame.addr`이 다름 - `out_addr`엔 실제 프레임 주소가 채워짐 |
| `SECURE_FRAME_ERR_NO_KEY` (-3) | `key_store`에 등록된 키 없음 |
| `SECURE_FRAME_ERR_HMAC` (-4) | HMAC 불일치 - 잘못된 키이거나 프레임이 변조됨 |
| `SECURE_FRAME_ERR_CRC` (-5) | 복호화 후 CRC16 불일치 (카운터 어긋남 의심, 위 참고) |

#### secure_frame_crc16

```c
uint16_t secure_frame_crc16(const uint8_t *buf, size_t len);
```

**매개변수**: `buf`/`len` [in].\
**설명**: 표준 Modbus CRC16(다항식 0xA001, 하위 바이트 먼저). `do_self_test()`가 `secure_frame_encrypt_and_build()`를 거치지 않고 직접 테스트 ADU를 구성할 때 필요해서 공개 함수로 사용. 특별한 예외/경계 조건 없음(모든 입력에 대해 항상 성공).

### 4.5 modbus/modbus_pdu.h

지원 함수 코드 8종:

| 코드 | 이름 | 요청 PDU(함수코드 제외) | 응답 PDU(함수코드 제외) | `value_or_qty` 의미 |
| --- | --- | --- | --- | --- |
| 0x01 | Read Coils | addr(2)+qty(2) | byte_count(1)+data | 읽을 개수 |
| 0x02 | Read Discrete Inputs | addr(2)+qty(2) | byte_count(1)+data | 읽을 개수 |
| 0x03 | Read Holding Registers | addr(2)+qty(2) | byte_count(1)+data(2×qty) | 읽을 개수 |
| 0x04 | Read Input Registers | addr(2)+qty(2) | byte_count(1)+data(2×qty) | 읽을 개수 |
| 0x05 | Write Single Coil | addr(2)+value(2, 0x0000/0xFF00) | 요청과 동일(echo) | 0=OFF, 0이 아니면 ON |
| 0x06 | Write Single Register | addr(2)+value(2) | 요청과 동일(echo) | 레지스터 값(0-65535) |
| 0x0F | Write Multiple Coils | addr(2)+qty(2)+byte_count(1)+data | addr(2)+qty(2) | 쓸 코일 개수 (값은 자동 생성) |
| 0x10 | Write Multiple Registers | addr(2)+qty(2)+byte_count(1)+data(2×qty) | addr(2)+qty(2) | 쓸 레지스터 개수 (값은 자동 생성) |

데모용 데이터 모델: `holding_registers`/`input_registers`/`coils`/`discrete_inputs` 각 128개(주소 0~127), 첫 사용 시 선형 패턴으로 초기화(`holding[i]=0x1000+i` 등)되어 실제 값처럼 보이는 데이터를 즉시 읽을 수 있음. quantity 상한(`MODBUS_MAX_READ_BITS`=2000, `MODBUS_MAX_WRITE_BITS`=1968, `MODBUS_MAX_READ_REGISTERS`=125, `MODBUS_MAX_WRITE_REGISTERS`=123)은 `libmodbus-master/src/modbus.h`와 동일한 값.

Modbus 예외 응답(`함수코드|0x80` + 예외코드):

| 예외 코드 | 이름 | 발생 조건 |
| --- | --- | --- |
| 0x01 | Illegal Function | 함수 코드가 위 8종 밖 |
| 0x02 | Illegal Data Address | 주소(+수량)가 128개 데모 테이블 범위를 벗어남 |
| 0x03 | Illegal Data Value | 요청 길이가 그 함수 코드의 최소 필드보다 짧음 / quantity가 0이거나 프로토콜 상한 초과 / byte_count가 quantity와 안 맞음 / 코일 값이 0x0000·0xFF00이 아님 |

#### modbus_build_request

```c
int modbus_build_request(uint8_t func, uint16_t addr, uint16_t value_or_qty,
                          uint8_t *out_pdu, size_t *out_pdu_len);
```

**매개변수**: `func` [in] 위 8종 중 하나(기본값 없음, 항상 명시해야 함), `addr` [in] 시작 주소(0~65535, 범위 자체는 형식상 항상 유효 — 아래 참고), `value_or_qty` [in] 함수 코드별 의미는 위 표 참고, `out_pdu` [out] 최소 `SECURE_FRAME_MAX_PDU`(253)바이트, `out_pdu_len` [out].\
**설명**: 마스터가 요청 PDU를 만드는 함수. 성공 시 1, 지원하지 않는 함수 코드이거나 `value_or_qty`가 그 함수의 quantity 상한(위 4.5 서두의 `MODBUS_MAX_*` 값)을 벗어나면 0을 반환하고 `out_pdu`는 건드리지 않는다.\

**동작/경계 조건**:

- **주소 유효성은 검사하지 않는다.** `addr`이 데모 테이블 범위(0~127)를 넘어가도 이 함수는 그냥 성공(1)해서 PDU를 만든다 — 실제 마스터가 슬레이브의 정확한 레지스터 맵을 미리 안다고 가정하지 않는 것과 같은 이유이며, 범위를 벗어나면 슬레이브가 `modbus_build_response()`에서 Illegal Data Address 예외로 정상 응답.
- `0x05`(Write Single Coil)는 `value_or_qty`가 0이면 OFF(`0x0000`), 0이 아닌 **어떤 값이든** ON(`0xFF00`)으로 취급한다 — `1`을 넣으나 `9999`를 넣으나 결과는 같다.
- `0x0F`/`0x10`(다중 쓰기)은 실제로 보낼 값을 지정할 방법이 없다 — 코일은 인덱스 패리티(`0,1,0,1,...`), 레지스터는 `주소+인덱스`로 자동 생성된다. 특정 값을 정확히 쓰고 싶다면 이 함수 대신 `0x06`(단일 레지스터 쓰기)을 반복 호출하거나 직접 PDU를 조립해야 한다.

```c
uint8_t pdu[SECURE_FRAME_MAX_PDU];
size_t pdu_len;

/* Read Holding Registers, 주소 0부터 2개 */
if (modbus_build_request(MODBUS_FUNC_READ_HOLDING_REGISTERS, 0, 2, pdu, &pdu_len)) {
    /* pdu == {0x03, 0x00, 0x00, 0x00, 0x02}, pdu_len == 5 */
}

/* Write Single Coil, 주소 3을 ON */
modbus_build_request(MODBUS_FUNC_WRITE_SINGLE_COIL, 3, 1, pdu, &pdu_len);
/* pdu == {0x05, 0x00, 0x03, 0xFF, 0x00} */
```

#### modbus_build_response

```c
int modbus_build_response(const uint8_t *req_pdu, size_t req_len,
                           uint8_t *resp_pdu, size_t *resp_len);
```

**매개변수**: `req_pdu`/`req_len` [in] `secure_frame_verify_and_decrypt()`가 돌려준 `out_pdu`/`out_pdu_len` 그대로, `resp_pdu` [out] 최소 `SECURE_FRAME_MAX_PDU` 바이트, `resp_len` [out].\
**설명**: 슬레이브가 요청을 해석해 데이터 모델에 적용(쓰기)/조회(읽기)하고 응답 PDU를 만드는 함수. `req_len`이 0이면(함수 코드조차 없음) 회신 불가로 0 반환 — 호출자는 회신을 생략해야 함. 그 외에는 항상 1을 반환하며 `resp_pdu`에 정상 응답 또는 예외 응답이 담김(호출자는 어느 쪽인지 구분할 필요 없이 그대로 암호화해 보내면 됨).\

**예외가 발생하는 정확한 조건** (`modbus_pdu.c`의 실제 검사 순서):

| 예외 | 발생 조건 (해당 함수 코드에서) |
| --- | --- |
| Illegal Data Value (0x03) | `req_len`이 그 함수의 최소 길이(읽기 5바이트, 단일 쓰기 5바이트, 다중 쓰기는 byte_count 포함 최소 6바이트)보다 짧음 |
| Illegal Data Value (0x03) | `qty`가 0이거나 `MODBUS_MAX_READ_BITS`/`MODBUS_MAX_WRITE_BITS`/`MODBUS_MAX_READ_REGISTERS`/`MODBUS_MAX_WRITE_REGISTERS` 상한 초과 |
| Illegal Data Value (0x03) | 다중 쓰기(0x0F/0x10)에서 요청에 실려온 `byte_count`가 `qty`로부터 계산한 기대값과 다름 |
| Illegal Data Value (0x03) | 단일 코일 쓰기(0x05)에서 값이 `0x0000`도 `0xFF00`도 아님 |
| Illegal Data Address (0x02) | `(uint32_t)addr + qty > MODBUS_TABLE_SIZE`(128) — `addr`/`qty`가 각각 `uint16_t`라 오버플로 없이 32비트로 안전하게 더해 비교 |
| Illegal Function (0x01) | 함수 코드가 위 8종 어디에도 속하지 않음 (`default` 분기) |

**성공 시 응답 형태**: 단일 코일/레지스터 쓰기(0x05/0x06) 성공은 요청 5바이트를 그대로 `memcpy`한 반사(echo) 응답이고, 다중 쓰기(0x0F/0x10) 성공은 수신 데이터를 반영하지 않고 `func+addr+qty` 5바이트만 새로 조립한 응답이다 — 두 경우 모두 표준 Modbus 사양과 일치.

```c
uint8_t resp[SECURE_FRAME_MAX_PDU];
size_t resp_len;

/* 위에서 만든 Read Holding Registers 요청(pdu, pdu_len)에 대한 응답 */
if (modbus_build_response(pdu, pdu_len, resp, &resp_len)) {
    /* 정상: resp == {0x03, 0x04, 0x10, 0x00, 0x10, 0x01} (레지스터 0,1의 초기값)
       예외라면 예: resp == {0x83, 0x02} (Illegal Data Address) */
}

/* 범위를 벗어난 주소로 Illegal Data Address 유발 */
{
    uint8_t bad_req[] = {0x03, 0x00, 0x7F, 0x00, 0x02}; /* addr=127, qty=2 -> 127+2=129 > 128 */
    modbus_build_response(bad_req, sizeof(bad_req), resp, &resp_len);
    /* resp == {0x83, 0x02} */
}
```

이 표와 예제는 §6.1의 `modbus_pdu_self_test()`(24개 케이스)로 전수 검증됨.

### 4.6 demo/ 공용 유틸리티

| 함수 | 매개변수 | 설명 |
| --- | --- | --- |
| `void exe_relative_path(const char *argv0, const char *filename, char *out, size_t out_size)` | argv0 [in], filename [in], out [out], out_size [in] | `"<argv0 디렉터리>/filename"` 문자열 조립. `keys.txt`/카운터 파일/로그 파일을 실행 파일 위치에 고정하는 데 사용 |
| `int demo_load_keys(const char *argv0)` | argv0 [in, NULL 허용] | `keys.txt`를 5가지 후보 경로로 순서대로 탐색해 로드 (cwd → 실행파일 옆 → `keymgmt/keys.txt` → `security/keymgmt/keys.txt` → `../keymgmt/keys.txt`). 불러온 항목 수(>0) 또는 실패 시 <=0 반환 |
| `long modbus_t35_us(long baud)` | baud [in] | Modbus RTU 스펙의 T3.5 유휴 간격을 마이크로초 단위로 계산 (실측 기반 20ms 최솟값 포함) |
| `void log_open(const char *path)` 외 `log_close_atexit`/`log_detail`/`log_summary`/`print_hex` | — | 파일 로깅 유틸리티 (`secure_send_demo`/`secure_recv_demo` 전용, §3 표 참고) |  

**기본값/경계 조건**: `demo_load_keys()`는 `argv0`가 `NULL`이어도 동작하지만 그 경우 "실행파일 옆" 경로 후보는 건너뛴다(나머지 4개 후보만 시도). 5개 후보를 모두 실패하면 0 이하를 반환하며 `key_store`는 변경되지 않는다. `modbus_t35_us()`는 계산값이 20ms(20000us) 미만이면 20ms로 올림하므로, `baud`에 어떤 값을 넣어도(0 포함) 반환값은 항상 20000 이상이다. `log_open()`을 호출하지 않고 `log_detail`/`log_summary`를 호출하면(파일이 안 열려 있으면) 해당 로그는 버려진다. `main.c`는 파일 로그를 쓰지 않으므로 이 유틸리티들을 아예 쓰지 않고 자체 `printf` 기반 출력만 사용한다.

```c
/* secure_recv_demo.c의 실제 초기화 순서 (main.c는 demo_log 대신 printf만 사용) */
char log_path[512], ctr_path[512];

exe_relative_path(argv[0], "recv_log.txt", log_path, sizeof(log_path));
log_open(log_path);
atexit(log_close_atexit);

if (demo_load_keys(argv[0]) <= 0) {
    log_summary("Could not load keys.txt\n");
    return 1;
}

exe_relative_path(argv[0], "ctr_state_recv.dat", ctr_path, sizeof(ctr_path));
ctr_state_set_path(ctr_path);
ctr_state_load();

serial_port_open(&sp, argv[1], baud, (int) modbus_t35_us(baud));
```

---

## 5. 데모 프로그램 사용법

### 5.1 secure_demo (main.c)

```plaintext
1. 마스터/슬레이브 모드 전환
2. 키 초기화
3. 단위 테스트
4. 환경 설정
5. 실행 (보안 통신 1회 수행)
6. 종료
```

- **1. 모드 전환**: `is_master` 플래그를 뒤집음.
- **2. 키 초기화**: `demo_load_keys()`로 `keys.txt` 로드.
- **3. 단위 테스트**: 포트에 실제로 연결하지 않고 암호화/프레이밍 로직과 `modbus_build_response()`의 함수 코드별 분기까지 한 번에 검증. §6.1 참고.
- **4. 환경 설정**: 포트(빈 값=현재 유지, `-`=포트 없음/파일 폴백) → baud → slave 주소(마스터일 땐 보낼 대상, 슬레이브일 땐 자신의 주소) → 함수 코드(1/2/3/4/5/6/15/16 중 하나) → 시작 주소 → `value_or_qty`(함수 코드에 따라 라벨이 바뀜 — §4.5 표 참고).
- **5. 실행**: 마스터면 §4.5의 함수 코드로 요청을 만들어 암호화 후 전송(포트 미설정 시 `sent_frame.bin`에 기록). 슬레이브면 수신 프레임을 검증/복호화하고, 실제 포트가 있으면 응답까지 암호화해 회신(포트 없이 파일로 읽은 경우는 검증/복호화만).

### 5.2 secure_send_demo / secure_recv_demo

```bash
secure_send_demo [port] [baud] [count]     # 포트 생략 시 sent_frame.bin에 기록
secure_recv_demo port [baud] [count]       # 포트 필수
```

`secure_send_demo`는 함수 0x10(Write Multiple Registers) 프레임을 레지스터 1개~123개까지 크기를 늘려가며 `count`번 전송해 모든 크기에서 프레임이 정상 생성되는 지 테스트한다(§4.5의 다른 함수 코드는 다루지 않음). `secure_recv_demo`는 실제 포트에서 프레임을 받아 검증/복호화하고 §4.5 로직으로 응답까지 회신한다.

---

## 6. 테스트 방법

### 6.1 단위 테스트 (secure_demo 옵션 3, `do_self_test()`)

하드웨어 없이 한 프로세스 안에서 공개 API를 직접 호출해 검증하는 세 개의 체크로 구성:

- **encrypt-path 체크** (테스트 주소 `0xF0`, `DIR_MASTER_TO_SLAVE`): `secure_frame_encrypt_and_build()`를 호출한 뒤, 알고 있는 `ctr_low=0`으로 직접 HMAC/복호화/CRC를 검증.
- **decrypt-path 체크** (테스트 주소 `0xF0`, `DIR_SLAVE_TO_MASTER`): `ctr_low=0`으로 직접 만든 프레임을 `secure_frame_verify_and_decrypt()`에 넘겨 검증.
- **`modbus_build_response()` 체크**: Modbus 요청에 따라 정상 및 예외 응답을 제대로 생성하는지 검증 (`modbus_pdu_self_test()`, §4.5·§2 `modbus_pdu_selftest.c` 참고). §4.5의 8개 함수 코드 성공 경로(쓰기 4종은 쓰기 직후 같은 주소를 읽어 `coils[]`/`holding_registers[]`에 실제로 반영됐는지까지 확인), 3가지 예외 코드(Illegal Function/Data Address/Data Value), 그리고 경계 조건(테이블 크기 128 경계, 프로토콜 quantity 상한, 요청 길이 부족, 다중 쓰기 `byte_count` 불일치)까지 총 24개 케이스를 덮는다.

실행: `secure_demo` 실행 후 `3` 입력. 기대 출력:

```bash
Running crypto logic self-test (no serial port involved)...
PASS (encrypt path): secure_frame_encrypt_and_build -> parse -> HMAC verify -> decrypt -> CRC check OK (5 byte PDU, 41 byte wire frame)
PASS (decrypt path): hand-built frame -> secure_frame_verify_and_decrypt OK (5 byte PDU, 41 byte wire frame)
[PASS] 0x01 Read Coils success
[PASS] 0x02 Read Discrete Inputs success
[PASS] 0x03 Read Holding Registers success
[PASS] 0x04 Read Input Registers success
[PASS] boundary: addr+qty == table size (128) succeeds
[PASS] boundary: addr+qty == table size+1 (129) -> Illegal Data Address
[PASS] boundary: qty == protocol max (125) succeeds
[PASS] boundary: qty == protocol max+1 (126) -> Illegal Data Value
[PASS] boundary: req_len < 5 -> Illegal Data Value
[PASS] exception: qty=0 -> Illegal Data Value
[PASS] exception: addr+qty > table size -> Illegal Data Address
[PASS] exception: unsupported function code -> Illegal Function
[PASS] boundary: Write Single Coil invalid value -> Illegal Data Value
[PASS] boundary: Write Multiple Coils byte_count mismatch -> Illegal Data Value
[PASS] boundary: Write Multiple Registers byte_count mismatch -> Illegal Data Value
[PASS] boundary: Write Multiple Coils addr+qty overflow -> Illegal Data Address
[PASS] 0x05 Write Single Coil success
[PASS] 0x05 Write Single Coil actually persisted (read-back)
[PASS] 0x06 Write Single Register success
[PASS] 0x06 Write Single Register actually persisted (read-back)
[PASS] 0x0F Write Multiple Coils success
[PASS] 0x0F Write Multiple Coils actually persisted (read-back)
[PASS] 0x10 Write Multiple Registers success
[PASS] 0x10 Write Multiple Registers actually persisted (read-back)
24 passed, 0 failed (24 total)
Self-test: ALL PASS
```

같은 프로세스 안에서 여러 번 실행해도(옵션 3을 반복 선택) 매번 PASS해야 정상.

### 6.2 파일 왕복 테스트 (하드웨어 불필요)

포트를 설정하지 않은 상태에서:

1. 마스터로 `2`(키 초기화) → `4`(환경 설정, 원하는 함수 코드/주소/수량 입력) → `5`(실행) — `sent_frame.bin`에 씀.
2. 새 프로세스(또는 `1`로 모드 전환)에서 `2` → `5`(실행) — `sent_frame.bin`을 읽어 검증/복호화. `Recovered PDU`가 §4.5 표대로 나오는지 확인.

**한계**: 포트가 없으면(`sp == NULL`) 슬레이브가 응답을 만들지 않으므로, 이 방법은 요청 방향(`DIR_MASTER_TO_SLAVE`)의 PDU 인코딩만 검증한다. 응답 생성(`modbus_build_response()`)은 이 방법으로 닿지 않으므로 §6.1의 단위 테스트로 검증한다.

### 6.3 실제 장비(Pi) 검증 절차

SSH 연결이 되어있는 CM5 기기에서 검증하려면 git으로 소스를 clone해 빌드한다.

**최초 설치**:

```bash
ssh <pi-host>
git clone https://github.com/siwoncool0530/modbus_security.git ~/security
cd ~/security
git checkout main
```

`keys.txt`는 `.gitignore` 대상이라 clone에 안 들어오므로 필요 시 별도로 옮겨야 한다(개발 머신에서):

```bash
scp keymgmt/keys.txt <pi-host>:~/security/keymgmt/keys.txt
```

빌드 (Pi는 aarch64라 Makefile이 자동으로 NEON 백엔드 선택):

```bash
make            # secure_send_demo, secure_recv_demo, secure_demo 모두 빌드
# NEON 관련 문제 있으면: make clean && make NO_NEON=1
```

실행:

```bash
./secure_demo          # 대화형 (마스터/슬레이브, 셀프테스트 등)
./secure_recv_demo /dev/ttyAMA0 115200
```

**이후 업데이트 필요 시**:

```bash
cd ~/security
git pull origin main
make clean && make
```

- `git remote -v`로 origin이 실제로 설정됐는지 먼저 확인 (clone했다면 자동으로 설정됨, 새로 `git remote add origin ...`을 할 필요는 없음).
- `keys.txt`, `ctr_state*.dat` 둘 다 `.gitignore` 대상이라 `git pull`로 덮어써지지 않는다 — 카운터 상태와 로컬 키 편집분 모두 안전.
- 로컬에 커밋 안 된 변경사항이 있으면 `git pull`이 충돌할 수 있으니, 그 전에 `git status`로 확인 권장.

### 6.4 체크리스트

- [ ] 단위 테스트(옵션 3) 여러 번 연속 실행 시 매번 `ALL PASS`
- [ ] 슬레이브 주소를 프레임과 다르게 설정하면 `Frame addressed to slave X, not us (configured as Y) -- ignoring`로 무시됨
- [ ] §4.5의 8개 함수 코드 모두 `환경 설정` → `실행`으로 요청 PDU가 표대로 만들어짐 (§6.2)
- [ ] Pi에서 위 항목들을 다시 실행해도 동일하게 PASS (§6.3)

---

## 7. 참조 문헌

1. modbus.org, "MODBUS over Serial Line Specification and Implementation Guide V1.02," 2006. ([modbusoverserial.pdf](modbusoverserial.pdf))
2. modbus.org, "MODBUS APPLICATION PROTOCOL SPECIFICATION V1.1b3," 2012. ([modbusprotocolspecification.pdf](modbusprotocolspecification.pdf))
3. 국가보안기술연구소, "128비트 블록암호 LEA 규격서," 2013.
4. D. Hong, J.-K. Lee, D.-C. Kim, D. Kwon, K. H. Ryu and D.-G. Lee, "LEA: A 128-Bit Block Cipher for Fast Encryption on Common Processors," in International Workshop on Information Security Applications, 2013. ([LEA A 128-Bit Block Cipher for Fast Encryption on Common Processors-English.pdf](LEA%20A%20128-Bit%20Block%20Cipher%20for%20Fast%20Encryption%20on%20Common%20Processors-English.pdf))
5. D.-C. Kim, D. Hong, J.-k. Lee, W.-H. Kim and D. Kwon, "LSH: A New Fast Secure Hash Function Family," in International Conference on Information Security and Cryptology, 2014. ([LSH A New Fast Secure Hash Function Family.pdf](LSH%20A%20New%20Fast%20Secure%20Hash%20Function%20Family.pdf))
6. 국가보안기술연구소, "해시함수 LSH 규격서," 2014.
7. 국가보안기술연구소, "블록암호 LEA 소스코드 사용 매뉴얼(v1.0)," 2015. ([블록암호 LEA 소스코드 사용 매뉴얼(v1.0).pdf](%EB%B8%94%EB%A1%9D%EC%95%94%ED%98%B8%20LEA%20%EC%86%8C%EC%8A%A4%EC%BD%94%EB%93%9C%20%EC%82%AC%EC%9A%A9%20%EB%A7%A4%EB%89%B4%EC%96%BC(v1.0).pdf))
8. 국가보안기술연구소, "LSH 소스코드 사용 매뉴얼(v1.0)," 2016. ([해시함수 LSH 소스코드 사용 매뉴얼(v1.0).pdf](%ED%95%B4%EC%8B%9C%ED%95%A8%EC%88%98%20LSH%20%EC%86%8C%EC%8A%A4%EC%BD%94%EB%93%9C%20%EC%82%AC%EC%9A%A9%20%EB%A7%A4%EB%89%B4%EC%96%BC(v1.0).pdf))
