# modbus_security

## 개요

이 프로젝트는 MODBUS RTU 통신에 기밀성(암호화)과 무결성/인증(HMAC)을 더하여 종단간 암호화를 달성하는 데에 그 목적이 있다. 국산 경량 블록 암호인 LEA-CTR을 활용하여 프레임을 암호화하고, 국산 해시함수 HMAC-LSH256 인증을 사용하여 무결성 및 인증을 보강하여 암호화 된 프레임을 전송 및 수신, 암호화 및 복호화를 진행한다.

## 폴더 구조

```plaintext
docs/      매뉴얼 및 참고 문헌
crypto/    LEA, LSH/HMAC 원시 함수
keymgmt/   키 테이블 + 방향별(m2s/s2m/bc) CTR 카운터 상태
framing/   [addr|ciphertext|hmac] 와이어 프레임 구조
modbus/    PDU 내용물 (함수 코드, 코일/레지스터 데이터 모델, 예외 응답)
demo/      실행 데모
```

## 와이어 프레임 구조

```plaintext
[addr(1)][ciphertext = LEA-CTR(addr + PDU + CRC16)][hmac(32)]
```

- `addr`: 평문으로 한 번 더 앞에 붙음 - 복호화 전에 프레임을 라우팅해야 하므로 필요.
- `ciphertext`: Modbus ADU(주소+PDU+CRC16) 전체를 LEA-CTR로 암호화한 암호문. CTR 카운터 자체는 전송되지 않고 송수신측 양쪽이 `keymgmt/ctr_state.h`로 각자 추적.
- `hmac`: `addr || ciphertext`에 대한 HMAC-LSH256 (32바이트).

## 소스코드 구성

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
| `modbus_pdu_self_test.h`/`modbus_pdu_self_test.c` | 요청 PDU 기반 응답(예외 응답) PDU 정상 생성 여부 테스트 |

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

## 환경 구축

### Pi 최초 설치 (SSH 이용)

```bash
ssh <pi-host>
git clone https://github.com/siwoncool0530/modbus_security.git ~/security
cd ~/security
git checkout main   # 필요하면 다른 브랜치로 (dedup-refactor / modbus-function-codes / test)
```

keys.txt는 .gitignore 대상이므로 필요 시 별도로 옮겨야 함: 개발 머신에서

```bash
scp keymgmt/keys.txt <pi-host>:~/security/keymgmt/keys.txt
```

빌드 (Pi는 aarch64라 Makefile이 자동으로 NEON 백엔드 선택):

```bash
make            # NEON 관련 문제 있으면: make clean && make NO_NEON=1
```

실행:

```bash
./secure_demo
```

### make가 없는 경우

make가 없는 경우 gcc 컴파일러 이용 다음과 같이 컴파일:

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

## 테스트 방법

```bash
----------------------------
[master] mode, keys: not loaded, port: (none), slave addr: 1 
1. 마스터/슬레이브 모드 전환
2. 키 초기화
3. 단위 테스트
4. 환경 설정
5. 실행 (보안 통신 1회 수행)
6. 종료
----------------------------    
```

1. 터미널 두 개에서 프로그램 실행한다.
2. 하나의 프로세스는 master로, 하나의 프로세스는 옵션 1을 입력해 slave로 설정한다.
3. 옵션 2를 입력, key 파일을 불러온다.
4. 옵션 3을 통해 테스트를 진행한다.
5. master측에서 옵션 4를 입력, 환경 설정으로 port, baud rate, slave addr, Function code 선택한다. slave측도 환경 설정을 통해 port, baud rate, slave addr 입력 및 설정한다.
6. slave측에서 응답 대기하도록 옵션 5를 입력하여 실행하고, master에서 5를 입력한 후 전송 및 응답 결과를 확인한다.
