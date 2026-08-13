/* 수신 측: 시리얼 포트를 감시하다가 도착한 프레임을 가져와 HMAC을 검증, LEA-CTR로 복호화한 뒤
    복원된 Modbus CRC16을 확인. 실제 하드웨어를 통한 왕복 검증.

   사용법: secure_recv_demo.exe port [baud] [count]
     Windows: secure_recv_demo.exe COM4 9600 5
     Linux:   ./secure_recv_demo /dev/ttyUSB1 9600 5
   count(기본값 1)는 한 번 실행에서 최대 이만큼의 프레임을 수신 (수신이 타임아웃되면 조기 종료)

   카운터 관련 유의사항: CTR이 오가지 않으므로, 송신 측의 시퀀스를 그대로 따라가는 방식으로만 카운터를 재구성 가능
   동일한 keys.txt로 만들어진 자체 카운터 파일(ctr_state_recv.dat)을 유지하며 프레임을 수신할 때마다 한 번씩 값을 증가시킴.
   송신 측이 암호화한 모든 프레임이 순서대로 빠짐없이 도착해야만 동기화 유지. 프레임 하나라도 유실되면 동기화 깨짐. */

#include "../framing/secure_frame.h"
#include "../keymgmt/key_store.h"
#include "../keymgmt/ctr_state.h"
#include "../modbus/modbus_pdu.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "serial_port.h"
#include "demo_log.h"
#include "key_paths.h"

#define DEFAULT_BAUD 9600

/* 프레임 하나를 수신하여 검증하고 복호화한다. 반환 코드:
     0 - 성공 (HMAC과 CRC 모두 정상)
    -1 - 프레임은 도착했지만 거부됨 (형식 오류/HMAC/CRC) -- 다음 프레임 시도
     1 - 타임아웃, 아무것도 도착하지 않음 -- 실행 종료
     2 - 포트에서 I/O 오류 발생 -- 실행 종료 */
static int receive_one_frame(serial_port_t *sp)
{
    uint8_t rx_buf[SECURE_FRAME_MAX_WIRE_LEN];
    long rx_len;
    uint8_t addr;
    size_t ciphertext_len;
    uint8_t pdu[SECURE_FRAME_MAX_PDU];
    size_t pdu_len;
    uint16_t crc_calc, crc_recv;
    secure_frame_status_t status;

    rx_len = serial_port_read(sp, rx_buf, sizeof(rx_buf));
    if (rx_len < 0) {
        return 2;
    }
    if (rx_len == 0) {
        log_detail("Timed out -- no frame received\n");
        return 1;
    }

    print_hex("Received raw frame", rx_buf, rx_len);

    status = secure_frame_verify_and_decrypt(rx_buf, (size_t) rx_len, SECURE_FRAME_ANY_ADDR,
                                              DIR_MASTER_TO_SLAVE, &addr, &ciphertext_len,
                                              pdu, &pdu_len, &crc_calc, &crc_recv);
    if (status == SECURE_FRAME_ERR_MALFORMED) {
        log_detail("secure_frame_parse: malformed frame (%u bytes, too short "
                   "for addr+hmac)\n",
                   (unsigned int) rx_len);
        serial_port_drain(sp);
        return -1;
    }
    log_detail("Parsed: addr=%u ciphertext_len=%u\n", (unsigned int) addr, (unsigned int) ciphertext_len);

    switch (status) {
    case SECURE_FRAME_OK:
        break;
    case SECURE_FRAME_ERR_NO_KEY:
        log_detail("No key provisioned for slave %u\n", (unsigned int) addr);
        serial_port_drain(sp);
        return -1;
    case SECURE_FRAME_ERR_HMAC:
        log_detail("HMAC MISMATCH -- frame rejected\n");
        serial_port_drain(sp);
        return -1;
    case SECURE_FRAME_ERR_CRC:
        log_detail("CRC MISMATCH (calc %04X, recv %04X) -- wrong counter sync?\n", crc_calc, crc_recv);
        serial_port_drain(sp);
        return -1;
    case SECURE_FRAME_ERR_WRONG_ADDR:
    default:
        /* SECURE_FRAME_ANY_ADDR을 넘겼으므로 이 경로는 오지 않음. */
        serial_port_drain(sp);
        return -1;
    }
    log_detail("HMAC OK\n");
    log_detail("CRC OK\n");
    print_hex("Recovered PDU", pdu, pdu_len);

    /* 요청을 검증/복호화했으니 슬레이브 입장에서 실제 코일/레지스터 모델에 적용(쓰기)하거나
       조회(읽기)해 정상 응답 또는 Modbus 예외 응답을 만든다 (modbus_pdu.c 참고).
       DIR_SLAVE_TO_MASTER 방향 키로 암호화해 같은 포트로 회신 -- 이제야 s2m 방향이 실제로
       사용됨. 함수 코드조차 알 수 없을 만큼 짧은 요청이면 회신을 생략. */
    {
        uint8_t reply_pdu[SECURE_FRAME_MAX_PDU];
        size_t reply_pdu_len;
        uint8_t reply_wire[SECURE_FRAME_MAX_WIRE_LEN];
        size_t reply_wire_len;

        if (!modbus_build_response(pdu, pdu_len, reply_pdu, &reply_pdu_len)) {
            log_detail("Request too short to identify a function code (%u bytes) -- skipping reply\n",
                       (unsigned int) pdu_len);
        } else if (secure_frame_encrypt_and_build(addr,
                                                    reply_pdu,
                                                    reply_pdu_len,
                                                    DIR_SLAVE_TO_MASTER,
                                                    reply_wire,
                                                    &reply_wire_len) != 0) {
            log_detail("reply: encrypt failed (no s2m key for slave %u?)\n", (unsigned int) addr);
        } else if (serial_port_write(sp, reply_wire, reply_wire_len) != 0) {
            log_detail("reply: write failed\n");
        } else {
            print_hex("Sent reply wire frame", reply_wire, reply_wire_len);
            log_detail("Reply sent (%u bytes)\n", (unsigned int) reply_wire_len);
        }
    }

    return 0;
}

int main(int argc, char **argv)
{
    serial_port_t sp;
    long baud;
    int count, i;
    int loaded;
    int ok = 0, failed = 0;

    {
        char log_path[512];
        exe_relative_path(argv[0], "recv_log.txt", log_path, sizeof(log_path));
        log_open(log_path);
        atexit(log_close_atexit);
    }

    if (argc < 2) {
        log_summary("Usage: %s PORT [baud] [count]\n", argv[0]);
        return 1;
    }
    baud = argc > 2 ? strtol(argv[2], NULL, 10) : DEFAULT_BAUD;
    count = argc > 3 ? (int) strtol(argv[3], NULL, 10) : 1;
    if (count < 1) {
        count = 1;
    }

    loaded = demo_load_keys(argv[0]);
    if (loaded <= 0) {
        log_summary("Could not load keys.txt (tried cwd, next to the executable, "
                     "keymgmt/keys.txt, security/keymgmt/keys.txt, and ../keymgmt/keys.txt)\n");
        return 1;
    }
    log_summary("Loaded %d key entries\n", loaded);

    {
        char ctr_path[512];
        exe_relative_path(argv[0], "ctr_state_recv.dat", ctr_path, sizeof(ctr_path));
        ctr_state_set_path(ctr_path);
    }
    ctr_state_load();

    /* 실제 Modbus T3.5 유휴 간격을 baud로부터 계산 (예: 115200 baud -> 약 334us). */
    if (serial_port_open(&sp, argv[1], baud, (int) modbus_t35_us(baud)) != 0) {
        return 1;
    }
    log_summary("Listening on %s @ %ld baud (up to 30s for first byte)...\n", argv[1], baud);

    for (i = 0; i < count; i++) {
        int rc;
        log_detail("--- frame %d/%d ---\n", i + 1, count);
        rc = receive_one_frame(&sp);
        if (rc == 0) {
            ok++;
            log_summary("%d/%d frame: success\n", i + 1, count);
        } else if (rc == -1) {
            failed++;
            log_summary("%d/%d frame: fail\n", i + 1, count);
        } else {
            log_summary("%d/%d frame: %s\n", i + 1, count, rc == 1 ? "timeout" : "io-error");
            break; /* 타임아웃/IO 오류 */
        }
    }

    serial_port_close(&sp);

    if (count > 1) {
        log_summary("=== %d/%d frames OK ===\n", ok, ok + failed);
    }

    return (ok > 0) ? 0 : 1;
}
