/* 송신(마스터 역할): 평문 Modbus ADU를 만들어 secure_frame_encrypt_and_build()(LEA-CTR 암호화 +
    HMAC-LSH256)를 통과시킨 뒤, 결과 프레임을 시리얼 포트로 내보내고, 같은 포트에서 슬레이브의
    회신(secure_recv_demo.c가 DIR_SLAVE_TO_MASTER로 암호화해 보냄)을 기다려 검증/복호화까지 함 --
    프레임 성공 여부는 이제 요청+회신 왕복 전체에 달려 있음.
    인자로 포트가 주어지지 않으면 sent_frame.bin에 기록하여 실제 하드웨어 없이도 테스트 가능
    (이 경우 회신은 당연히 없으므로 검증하지 않음).

   사용법: secure_send_demo.exe [port] [baud] [count]
     Windows: secure_send_demo.exe COM3 9600 5
     Linux:   ./secure_send_demo /dev/ttyUSB0 9600 5
   count(기본값 1)만큼 프레임을 전송하되, 프레임 간 대기시간은 baud로부터 산정(수신측
   modbus_t35_us()와 같은 공식 + 안전 여유 2배)하여, 수신 측의 유휴 간격 프레이밍 하에서
   하나로 합쳐지지 않고 별개의 프레임으로 도착하도록 함. Modbus PDU 크기는 실행 전체에 걸쳐 레지스터 1개에서
   MAX_REGISTERS 상한까지 선형으로 늘어나므로(단일 프레임 실행 시 최대 크기 프레임만 전송)
   가장 작은 프레임부터 가장 큰 프레임까지 모두 테스트 가능.
 */

#include "../framing/secure_frame.h"
#include "../keymgmt/key_store.h"
#include "../keymgmt/ctr_state.h"
#include "serial_port.h"
#include "demo_log.h"
#include "key_paths.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define DEFAULT_BAUD 115200

static int inter_frame_gap_ms(long baud)
{
    long gap_us = modbus_t35_us(baud) * 2; /* 수신측 자체 임계값보다 여유 있게 */
    return (int) ((gap_us + 999) / 1000);  /* serial_sleep_ms()용으로 올림 */
}

/* 요청 프레임을 보내고 같은 포트에서 슬레이브의 회신(DIR_SLAVE_TO_MASTER)을
   기다려 검증/복호화까지 마친다. 프레임 성공 여부는 이제 왕복 전체(요청 전송
   + 회신 HMAC/CRC 통과)에 달려 있음 -- s2m 방향이 실제로 이 경로에서만
   쓰이므로, 이게 성공해야 그 방향의 암호화/카운터 로직이 검증된 것. */
static int send_request_and_verify_reply(const char *port_name, long baud, uint8_t slave_addr,
                                          const uint8_t *frame, size_t len)
{
    serial_port_t sp;
    uint8_t rx_buf[SECURE_FRAME_MAX_WIRE_LEN];
    long rx_len;
    uint8_t reply_addr;
    uint8_t reply_pdu[SECURE_FRAME_MAX_PDU];
    size_t reply_pdu_len;
    uint16_t crc_calc, crc_recv;
    secure_frame_status_t status;

    if (serial_port_open(&sp, port_name, baud, (int) modbus_t35_us(baud)) != 0) {
        return -1;
    }
    if (serial_port_write(&sp, frame, len) != 0) {
        serial_port_close(&sp);
        return -1;
    }
    log_detail("Sent %u bytes to %s @ %ld baud, waiting for reply...\n", (unsigned int) len, port_name, baud);

    rx_len = serial_port_read(&sp, rx_buf, sizeof(rx_buf));
    serial_port_close(&sp);

    if (rx_len < 0) {
        log_detail("reply: I/O error waiting for reply\n");
        return -1;
    }
    if (rx_len == 0) {
        log_detail("reply: timed out, no reply received\n");
        return -1;
    }
    print_hex("Received reply raw frame", rx_buf, rx_len);

    status = secure_frame_verify_and_decrypt(rx_buf, (size_t) rx_len, slave_addr, DIR_SLAVE_TO_MASTER,
                                              &reply_addr, NULL, reply_pdu, &reply_pdu_len,
                                              &crc_calc, &crc_recv);
    switch (status) {
    case SECURE_FRAME_OK:
        break;
    case SECURE_FRAME_ERR_MALFORMED:
        log_detail("reply: malformed frame (%u bytes, too short for addr+hmac)\n", (unsigned int) rx_len);
        return -1;
    case SECURE_FRAME_ERR_WRONG_ADDR:
        log_detail("reply: addr mismatch (expected %u, got %u)\n",
                   (unsigned int) slave_addr, (unsigned int) reply_addr);
        return -1;
    case SECURE_FRAME_ERR_NO_KEY:
        log_detail("reply: no s2m key provisioned for slave %u\n", (unsigned int) slave_addr);
        return -1;
    case SECURE_FRAME_ERR_HMAC:
        log_detail("reply: HMAC MISMATCH\n");
        return -1;
    case SECURE_FRAME_ERR_CRC:
    default:
        log_detail("reply: CRC MISMATCH (calc %04X, recv %04X)\n", crc_calc, crc_recv);
        return -1;
    }
    log_detail("reply: HMAC OK\n");
    log_detail("reply: CRC OK\n");
    print_hex("Recovered reply PDU", reply_pdu, reply_pdu_len);

    return 0;
}

static int send_to_file(const char *path, const uint8_t *frame, size_t len)
{
    FILE *f = fopen(path, "wb");
    if (f == NULL) {
        return -1;
    }
    fwrite(frame, 1, len, f);
    fclose(f);
    log_detail("No port given -- wrote %u bytes to %s instead\n", (unsigned int) len, path);
    return 0;
}

int main(int argc, char **argv)
{
    uint8_t slave_addr = 0x01;
    uint8_t wire_frame[SECURE_FRAME_MAX_WIRE_LEN];
    size_t wire_len;
    int loaded;
    long baud;
    int count;
    int i;

    {
        char log_path[512];
        exe_relative_path(argv[0], "send_log.txt", log_path, sizeof(log_path));
        log_open(log_path);
        atexit(log_close_atexit);
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
        exe_relative_path(argv[0], "ctr_state.dat", ctr_path, sizeof(ctr_path));
        ctr_state_set_path(ctr_path);
    }
    ctr_state_load(); /* fine if it fails -- falls back to keys.txt's initial_ctr */

    baud = argc > 2 ? strtol(argv[2], NULL, 10) : DEFAULT_BAUD;
    count = argc > 3 ? (int) strtol(argv[3], NULL, 10) : 1;
    if (count < 1) {
        count = 1;
    }

    {
        int ok = 0, failed = 0;

        for (i = 0; i < count; i++) {
            /* 평문 Modbus PDU
               Function code 0x10(여러 레지스터 쓰기),
               시작 주소는 레지스터 0x0001,
               레지스터 개수는 실행 전체에 걸쳐 1부터 MAX_REGISTERS(123, Function code에 따라 Modbus
               규격 문서로 명시한 상한 6 + 123*2 = 252바이트로 최대 SECURE_FRAME_MAX_PDU/253보다 1바이트 작음)
               까지 순차적으로 늘어남. 여러 프레임으로 실행하면 가장 작은 프레임부터 가장 큰 프레임까지 실행 가능.
               단일 프레임 실행은 최대 크기만 테스트하도록 그대로 유지.
               byte_count 필드와 실제 데이터 길이가 서로 어긋나지 않도록 프로그램으로 생성 */

#define MAX_REGISTERS 123
            int regs = (count > 1)
                           ? 1 + (int) (((long) i * (MAX_REGISTERS - 1)) / (count - 1))
                           : MAX_REGISTERS;
            uint8_t plaintext_pdu[6 + MAX_REGISTERS * 2];
            size_t pdu_len = (size_t) (6 + regs * 2);
            int reg;
            int frame_ok;

            plaintext_pdu[0] = 0x10;                    /* function code: write multiple registers */
            plaintext_pdu[1] = 0x00;                    /* starting address hi */
            plaintext_pdu[2] = 0x01;                    /* starting address lo */
            plaintext_pdu[3] = (uint8_t) (regs >> 8);   /* quantity of registers hi */
            plaintext_pdu[4] = (uint8_t) (regs & 0xFF); /* quantity of registers lo */
            plaintext_pdu[5] = (uint8_t) (regs * 2);    /* byte count */
            for (reg = 0; reg < regs; reg++) {
                uint16_t value = (uint16_t) (reg + i); /* 프레임마다 값은 달리함 */
                plaintext_pdu[6 + reg * 2] = (uint8_t) (value >> 8);
                plaintext_pdu[6 + reg * 2 + 1] = (uint8_t) (value & 0xFF);
            }

            log_detail("--- frame %d/%d (%d registers, %u byte PDU) ---\n",
                        i + 1, count, regs, (unsigned int) pdu_len);
            print_hex("Plaintext PDU", plaintext_pdu, pdu_len);

            frame_ok = 0;
            if (secure_frame_encrypt_and_build(slave_addr,
                                                plaintext_pdu,
                                                pdu_len,
                                                DIR_MASTER_TO_SLAVE,
                                                wire_frame,
                                                &wire_len) != 0) {
                log_detail("secure_frame_encrypt_and_build failed "
                            "(no key provisioned for slave %u?)\n",
                            (unsigned int) slave_addr);
            } else {
                print_hex("Wire frame [addr|ciphertext|hmac]", wire_frame, wire_len);

                if (argc > 1) {
                    frame_ok = (send_request_and_verify_reply(argv[1], baud, slave_addr, wire_frame, wire_len) == 0);
                } else {
                    char path[64];
                    snprintf(path, sizeof(path), "sent_frame_%d.bin", i);
                    frame_ok = (send_to_file(count > 1 ? path : "sent_frame.bin",
                                              wire_frame, wire_len) == 0);
                }
            }

            log_summary("%d/%d frame: %s\n", i + 1, count, frame_ok ? "success" : "fail");
            if (frame_ok) {
                ok++;
            } else {
                failed++;
            }

            if (i + 1 < count) {
                serial_sleep_ms(inter_frame_gap_ms(baud));
            }
        }

        if (count > 1) {
            log_summary("=== %d/%d frames OK ===\n", ok, ok + failed);
        }

        return (failed == 0) ? 0 : 1;
    }
}
