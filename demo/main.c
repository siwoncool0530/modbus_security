// user wrapper for demo of secure send/recv
// 대화형 메뉴 하나로 secure_send_demo.c/secure_recv_demo.c와 같은 LEA-CTR + HMAC-LSH256
// 왕복 흐름을 그 자리에서 직접 수행 (별도 실행파일을 띄우지 않음).

#include "../framing/secure_frame.h"
#include "../keymgmt/key_store.h"
#include "../keymgmt/ctr_state.h"
#include "../crypto/lea.h"
#include "../crypto/lea_ctr.h"
#include "../crypto/hmac_lsh.h"
#include "serial_port.h"
#include "key_paths.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int is_master = 1;

static char config_port[64] = "";      /* 비어있으면 포트 없이 파일로 폴백 */
static long config_baud = 115200;
static uint8_t config_slave_addr = 0x01;
static int keys_loaded = 0;
static const char *g_argv0 = NULL;     /* demo_load_keys()의 실행 파일 상대 경로 탐색용 */

static void flush_stdin_line(void)
{
    int c;
    while ((c = getchar()) != '\n' && c != EOF) {
    }
}

/* secure_send_demo.c/secure_recv_demo.c의 log-file 기반 print_hex()와 달리 콘솔에 바로
   출력 -- main.c는 인터랙티브 도구라 로그 파일이 없고, 그 자리에서 바로 보여주는 게 맞음. */
static void print_hex(const char *label, const uint8_t *buf, size_t len)
{
    size_t i;
    printf("%s (%u bytes): ", label, (unsigned int) len);
    for (i = 0; i < len; i++) {
        printf("%02X ", buf[i]);
    }
    printf("\n");
}

static void do_key_init(void)
{
    int loaded = demo_load_keys(g_argv0);
    if (loaded <= 0) {
        printf("Could not load keys.txt (tried cwd, next to the executable, "
               "keymgmt/keys.txt, security/keymgmt/keys.txt, and ../keymgmt/keys.txt)\n");
        keys_loaded = 0;
        return;
    }
    printf("Loaded %d key entries from keys.txt\n", loaded);
    keys_loaded = 1;
}

/* 프레임 하나를 addr(DIR_MASTER_TO_SLAVE 키)로 검증/복호화하고 결과를 출력.
   sp가 NULL이 아니면(실시간 시리얼 수신) secure_recv_demo.c와 동일하게 DIR_SLAVE_TO_MASTER로
   암호화한 회신까지 같은 포트로 보냄. */
static void process_incoming_frame(const uint8_t *rx_buf, size_t rx_len, serial_port_t *sp)
{
    uint8_t addr;
    size_t ciphertext_len;
    uint8_t pdu[SECURE_FRAME_MAX_PDU];
    size_t pdu_len;
    uint16_t crc_calc, crc_recv;
    secure_frame_status_t status;

    status = secure_frame_verify_and_decrypt(rx_buf, rx_len, config_slave_addr, DIR_MASTER_TO_SLAVE,
                                              &addr, &ciphertext_len, pdu, &pdu_len, &crc_calc, &crc_recv);
    if (status == SECURE_FRAME_ERR_MALFORMED) {
        printf("Malformed frame (%u bytes, too short for addr+hmac)\n", (unsigned int) rx_len);
        return;
    }
    printf("Parsed: addr=%u ciphertext_len=%u\n", (unsigned int) addr, (unsigned int) ciphertext_len);

    switch (status) {
    case SECURE_FRAME_OK:
        break;
    case SECURE_FRAME_ERR_WRONG_ADDR:
        /* 실제 RS-485 버스에는 슬레이브가 여럿 달릴 수 있어 이 프레임이 우리 주소로 온 게
           아닐 수 있음 -- 그런 프레임은 (키가 있어도) 우리 것으로 처리하면 안 됨. */
        printf("Frame addressed to slave %u, not us (configured as %u) -- ignoring\n",
               (unsigned int) addr, (unsigned int) config_slave_addr);
        return;
    case SECURE_FRAME_ERR_NO_KEY:
        printf("No m2s key provisioned for slave %u\n", (unsigned int) addr);
        return;
    case SECURE_FRAME_ERR_HMAC:
        printf("HMAC MISMATCH -- frame rejected\n");
        return;
    case SECURE_FRAME_ERR_CRC:
    default:
        printf("CRC MISMATCH (calc %04X, recv %04X) -- wrong counter sync?\n", crc_calc, crc_recv);
        return;
    }
    printf("HMAC OK\n");
    printf("CRC OK\n");
    print_hex("Recovered PDU", pdu, pdu_len);

    if (sp != NULL && pdu_len >= 5) {
        uint8_t reply_pdu[5];
        uint8_t reply_wire[SECURE_FRAME_MAX_WIRE_LEN];
        size_t reply_wire_len;

        memcpy(reply_pdu, pdu, sizeof(reply_pdu));
        if (secure_frame_encrypt_and_build(addr, reply_pdu, sizeof(reply_pdu),
                                            DIR_SLAVE_TO_MASTER, reply_wire, &reply_wire_len) != 0) {
            printf("Reply encrypt failed -- no s2m key for slave %u\n", (unsigned int) addr);
        } else if (serial_port_write(sp, reply_wire, reply_wire_len) != 0) {
            printf("Reply write failed\n");
        } else {
            print_hex("Sent reply wire frame", reply_wire, reply_wire_len);
        }
    }

    printf("Slave processing OK\n");
}

static void run_as_master(void)
{
    uint8_t wire_frame[SECURE_FRAME_MAX_WIRE_LEN];
    size_t wire_len;
    /* 고정된 데모 PDU: function 0x10(여러 레지스터 쓰기), 시작주소 0x0001, 2개 레지스터 */
    uint8_t plaintext_pdu[10] = {0x10, 0x00, 0x01, 0x00, 0x02, 0x04, 0x00, 0x2A, 0x00, 0x2B};

    if (secure_frame_encrypt_and_build(config_slave_addr, plaintext_pdu, sizeof(plaintext_pdu),
                                        DIR_MASTER_TO_SLAVE, wire_frame, &wire_len) != 0) {
        printf("Encrypt failed -- no m2s key provisioned for slave %u\n", (unsigned int) config_slave_addr);
        return;
    }
    print_hex("Wire frame [addr|ciphertext|hmac]", wire_frame, wire_len);

    if (config_port[0] == '\0') {
        FILE *f = fopen("sent_frame.bin", "wb");
        if (f == NULL) {
            printf("Could not open sent_frame.bin for writing\n");
            return;
        }
        fwrite(wire_frame, 1, wire_len, f);
        fclose(f);
        printf("No port configured -- wrote %u bytes to sent_frame.bin\n", (unsigned int) wire_len);
        return;
    }

    {
        serial_port_t sp;
        uint8_t rx_buf[SECURE_FRAME_MAX_WIRE_LEN];
        long rx_len;
        uint8_t reply_addr;
        uint8_t reply_pdu[SECURE_FRAME_MAX_PDU];
        size_t reply_pdu_len;
        uint16_t crc_calc, crc_recv;
        secure_frame_status_t status;

        if (serial_port_open(&sp, config_port, config_baud, (int) modbus_t35_us(config_baud)) != 0) {
            printf("Could not open %s\n", config_port);
            return;
        }
        if (serial_port_write(&sp, wire_frame, wire_len) != 0) {
            printf("Write failed\n");
            serial_port_close(&sp);
            return;
        }
        printf("Sent %u bytes to %s @ %ld baud, waiting for reply...\n",
               (unsigned int) wire_len, config_port, config_baud);

        rx_len = serial_port_read(&sp, rx_buf, sizeof(rx_buf));
        serial_port_close(&sp);

        if (rx_len < 0) {
            printf("I/O error waiting for reply\n");
            return;
        }
        if (rx_len == 0) {
            printf("Timed out, no reply received\n");
            return;
        }
        print_hex("Received reply raw frame", rx_buf, rx_len);

        status = secure_frame_verify_and_decrypt(rx_buf, (size_t) rx_len, config_slave_addr, DIR_SLAVE_TO_MASTER,
                                                  &reply_addr, NULL, reply_pdu, &reply_pdu_len,
                                                  &crc_calc, &crc_recv);
        switch (status) {
        case SECURE_FRAME_OK:
            break;
        case SECURE_FRAME_ERR_MALFORMED:
            printf("Malformed reply frame\n");
            return;
        case SECURE_FRAME_ERR_WRONG_ADDR:
            printf("Reply addr mismatch (expected %u, got %u)\n",
                   (unsigned int) config_slave_addr, (unsigned int) reply_addr);
            return;
        case SECURE_FRAME_ERR_NO_KEY:
            printf("No s2m key provisioned for slave %u\n", (unsigned int) config_slave_addr);
            return;
        case SECURE_FRAME_ERR_HMAC:
            printf("Reply HMAC MISMATCH\n");
            return;
        case SECURE_FRAME_ERR_CRC:
        default:
            printf("Reply CRC MISMATCH (calc %04X, recv %04X)\n", crc_calc, crc_recv);
            return;
        }
        printf("Reply HMAC OK\n");
        printf("Reply CRC OK\n");
        print_hex("Recovered reply PDU", reply_pdu, reply_pdu_len);
        printf("Master exchange OK\n");
    }
}

static void run_as_slave(void)
{
    if (config_port[0] == '\0') {
        uint8_t rx_buf[SECURE_FRAME_MAX_WIRE_LEN];
        size_t rx_len;
        FILE *f = fopen("sent_frame.bin", "rb");
        if (f == NULL) {
            printf("No port configured and sent_frame.bin not found -- run as master first or set a port (option 4)\n");
            return;
        }
        rx_len = fread(rx_buf, 1, sizeof(rx_buf), f);
        fclose(f);
        printf("No port configured -- read %u bytes from sent_frame.bin\n", (unsigned int) rx_len);
        process_incoming_frame(rx_buf, rx_len, NULL); /* 회신 보낼 포트가 없으므로 검증/복호화만 수행 */
        return;
    }

    {
        serial_port_t sp;
        uint8_t rx_buf[SECURE_FRAME_MAX_WIRE_LEN];
        long rx_len;

        if (serial_port_open(&sp, config_port, config_baud, (int) modbus_t35_us(config_baud)) != 0) {
            printf("Could not open %s\n", config_port);
            return;
        }
        printf("Listening on %s @ %ld baud (up to 30s for first byte)...\n", config_port, config_baud);

        rx_len = serial_port_read(&sp, rx_buf, sizeof(rx_buf));
        if (rx_len < 0) {
            printf("I/O error\n");
            serial_port_close(&sp);
            return;
        }
        if (rx_len == 0) {
            printf("Timed out, nothing received\n");
            serial_port_close(&sp);
            return;
        }
        print_hex("Received raw frame", rx_buf, rx_len);
        process_incoming_frame(rx_buf, rx_len, &sp);
        serial_port_close(&sp);
    }
}

static void do_run_exchange(void)
{
    if (!keys_loaded) {
        printf("Load keys first (option 2).\n");
        return;
    }

    ctr_state_set_path(is_master ? "ctr_state.dat" : "ctr_state_recv.dat");
    ctr_state_load(); /* 없어도 무방 -- 처음 필요해지는 시점에 key_store의 initial_ctr로 대체 */

    if (is_master) {
        run_as_master();
    } else {
        run_as_slave();
    }
}

/* 암호화 로직 점검용 테스트: 하드웨어 없이 한 프로세스 안에서 공개 API
   (secure_frame_encrypt_and_build(), secure_frame_verify_and_decrypt())를 두 방향(m2s/s2m) 모두
   직접 호출해 검증한다. serial_port를 전혀 거치지 않으므로 통과해도 실제 RS-485 배선/포트
   (/dev/ttyAMA0, COM 포트 등) 상태는 확인하지 못함 -- 하드웨어/배선 확인은 옵션 4로 포트를
   설정한 뒤 옵션 5(실행)로 해야 한다.

   아래 두 체크가 서로 다른 테스트 주소(0xF0/0xF1)와 방향(m2s/s2m)을 쓰는 것은 ctr_state가
   (addr, dir)별로 하나뿐인 프로세스 전역 카운터 테이블이기 때문이다. 같은 (addr, dir)에
   대해 secure_frame_encrypt_and_build()를 부른 직후 secure_frame_verify_and_decrypt()를 또
   부르면, 그 함수 내부의 ctr_state_next_outgoing()이 두 번째로 호출되어 이미 전진된 다음
   카운터를 받아오게 되므로 복호화가 실패한다 (재현 방법: 옵션 3을 실제 함수 두 개로 같은
   주소에 대해 연달아 부르면 두 번째 호출이 CRC mismatch로 실패한다). 서로 다른 (addr, dir)
   슬롯을 쓰면 이 문제를 피하면서도 공개 함수를 그대로 검증할 수 있다. */
static void do_self_test(void)
{
    int ok = 1;
    int i;

    printf("Running crypto logic self-test (no serial port involved)...\n");

    /* --- encrypt-path check: 실제 secure_frame_encrypt_and_build()를 호출해 검증.
       0xF0/m2s는 이 프로세스에서 처음 쓰이므로 그 함수 내부의 ctr_state_next_outgoing()
       호출이 항상 0을 반환 -- 그 사실을 이용해 복호화는 secure_frame_verify_and_decrypt()를
       다시 부르지 않고(위 주석 참고) 알고 있는 ctr_low=0으로 직접 검증한다. */
    {
        const uint8_t addr = 0xF0;
        directional_keys_t dk;
        uint8_t pdu[5] = {0x03, 0x00, 0x00, 0x00, 0x02}; /* read holding registers, addr 0, qty 2 */
        uint8_t wire[SECURE_FRAME_MAX_WIRE_LEN];
        size_t wire_len;
        secure_frame_t parsed;
        uint8_t mac_input[SECURE_FRAME_ADDR_LEN + SECURE_FRAME_MAX_ADU];
        uint8_t expected_hmac[HMAC_LSH_FULL_SIZE];
        lea_key_schedule_t ks;
        uint8_t ctr_high[LEA_CTR_HIGH_SIZE];
        uint8_t plaintext_adu[SECURE_FRAME_MAX_ADU];
        uint16_t crc_calc, crc_recv;

        for (i = 0; i < KEY_SIZE; i++) {
            dk.enc_key[i] = (uint8_t) (0x10 + i);
            dk.mac_key[i] = (uint8_t) (0x20 + i);
        }

        /* 이 셀프 테스트가 같은 프로세스 안에서 여러 번 실행돼도(옵션 3을 반복 선택) 항상
           ctr_low=0부터 다시 시작하도록 리셋 -- 안 하면 두 번째 실행부터 이 (addr, dir)의
           카운터가 이미 전진해 있어 아래 수동 복호화의 ctr_low=0 가정이 깨진다. */
        ctr_state_reset(addr, DIR_MASTER_TO_SLAVE);

        if (key_store_provision(addr, DIR_MASTER_TO_SLAVE, &dk) != 0) {
            printf("FAIL (encrypt path): key_store_provision failed\n");
            ok = 0;
        } else if (secure_frame_encrypt_and_build(addr, pdu, sizeof(pdu), DIR_MASTER_TO_SLAVE,
                                                   wire, &wire_len) != 0) {
            printf("FAIL (encrypt path): secure_frame_encrypt_and_build failed\n");
            ok = 0;
        } else if (!secure_frame_parse(wire, wire_len, &parsed)) {
            printf("FAIL (encrypt path): secure_frame_parse rejected the frame it just built\n");
            ok = 0;
        } else {
            mac_input[0] = parsed.addr;
            memcpy(mac_input + SECURE_FRAME_ADDR_LEN, parsed.ciphertext, parsed.ciphertext_len);
            hmac_lsh256(dk.mac_key, KEY_SIZE, mac_input, SECURE_FRAME_ADDR_LEN + parsed.ciphertext_len,
                        expected_hmac);
            if (memcmp(expected_hmac, parsed.hmac, SECURE_FRAME_HMAC_LEN) != 0) {
                printf("FAIL (encrypt path): HMAC mismatch\n");
                ok = 0;
            } else {
                memset(ctr_high, 0, sizeof(ctr_high));
                lea_key_schedule(dk.enc_key, &ks);
                lea_ctr_crypt(&ks, ctr_high, 0, 0, parsed.ciphertext, plaintext_adu, parsed.ciphertext_len);

                crc_calc = secure_frame_crc16(plaintext_adu, parsed.ciphertext_len - SECURE_FRAME_CRC_LEN);
                crc_recv = (uint16_t) plaintext_adu[parsed.ciphertext_len - 2] |
                           ((uint16_t) plaintext_adu[parsed.ciphertext_len - 1] << 8);
                if (crc_calc != crc_recv) {
                    printf("FAIL (encrypt path): CRC mismatch after decrypt (calc %04X, recv %04X)\n",
                           crc_calc, crc_recv);
                    ok = 0;
                } else if (plaintext_adu[0] != addr ||
                           memcmp(plaintext_adu + SECURE_FRAME_ADDR_LEN, pdu, sizeof(pdu)) != 0) {
                    printf("FAIL (encrypt path): recovered PDU does not match what was sent\n");
                    ok = 0;
                } else {
                    printf("PASS (encrypt path): secure_frame_encrypt_and_build -> parse -> HMAC verify -> "
                           "decrypt -> CRC check OK (%u byte PDU, %u byte wire frame)\n",
                           (unsigned int) sizeof(pdu), (unsigned int) wire_len);
                }
            }
        }
    }

    /* --- decrypt-path check: 실제 secure_frame_verify_and_decrypt()를 호출해 검증하며,
       파일 왕복 테스트(마스터가 sent_frame.bin에 쓰고 슬레이브가 읽는 방식)로는 절대 닿지
       않는 DIR_SLAVE_TO_MASTER 방향까지 커버한다 (그 왕복은 항상 DIR_MASTER_TO_SLAVE만 씀).
       0xF1/s2m은 위 encrypt-path 체크와 다른 (addr, dir) 슬롯이라 독립적으로 새 것이므로,
       ctr_low=0으로 직접 만든 프레임을 실제 secure_frame_verify_and_decrypt()에 바로 넘겨도
       안전하다 (그 함수의 첫 ctr_state_next_outgoing() 호출도 0을 반환하므로 서로 맞음). */
    {
        const uint8_t addr = 0xF1;
        directional_keys_t dk;
        uint8_t pdu[5] = {0x10, 0x00, 0x01, 0x00, 0x02}; /* write multiple registers, addr 1, qty 2 */
        uint8_t plaintext_adu[SECURE_FRAME_MAX_ADU];
        size_t adu_len;
        uint16_t crc;
        secure_frame_t frame;
        uint8_t wire[SECURE_FRAME_MAX_WIRE_LEN];
        size_t wire_len;
        lea_key_schedule_t ks;
        uint8_t ctr_high[LEA_CTR_HIGH_SIZE];
        uint8_t mac_input[SECURE_FRAME_ADDR_LEN + SECURE_FRAME_MAX_ADU];
        uint8_t out_addr;
        uint8_t out_pdu[SECURE_FRAME_MAX_PDU];
        size_t out_pdu_len;
        uint16_t crc_calc, crc_recv;
        secure_frame_status_t status;

        for (i = 0; i < KEY_SIZE; i++) {
            dk.enc_key[i] = (uint8_t) (0x30 + i);
            dk.mac_key[i] = (uint8_t) (0x40 + i);
        }

        memset(ctr_high, 0, sizeof(ctr_high));
        plaintext_adu[0] = addr;
        memcpy(plaintext_adu + SECURE_FRAME_ADDR_LEN, pdu, sizeof(pdu));
        crc = secure_frame_crc16(plaintext_adu, SECURE_FRAME_ADDR_LEN + sizeof(pdu));
        plaintext_adu[SECURE_FRAME_ADDR_LEN + sizeof(pdu)] = (uint8_t) (crc & 0xFF);
        plaintext_adu[SECURE_FRAME_ADDR_LEN + sizeof(pdu) + 1] = (uint8_t) (crc >> 8);
        adu_len = SECURE_FRAME_ADDR_LEN + sizeof(pdu) + SECURE_FRAME_CRC_LEN;

        frame.addr = addr;
        frame.ciphertext_len = adu_len;
        lea_key_schedule(dk.enc_key, &ks);
        lea_ctr_crypt(&ks, ctr_high, 0, 1, plaintext_adu, frame.ciphertext, adu_len);

        mac_input[0] = frame.addr;
        memcpy(mac_input + SECURE_FRAME_ADDR_LEN, frame.ciphertext, adu_len);
        hmac_lsh256(dk.mac_key, KEY_SIZE, mac_input, SECURE_FRAME_ADDR_LEN + adu_len, frame.hmac);

        wire_len = secure_frame_build(&frame, wire);

        /* 위 encrypt-path 체크와 같은 이유로 리셋 -- 아래 secure_frame_verify_and_decrypt()
           호출이 이 (addr, dir)에 대해 처음 ctr_state_next_outgoing()을 부르는 것이어야
           위에서 직접 만든 ctr_low=0 프레임과 맞는다. */
        ctr_state_reset(addr, DIR_SLAVE_TO_MASTER);

        if (key_store_provision(addr, DIR_SLAVE_TO_MASTER, &dk) != 0) {
            printf("FAIL (decrypt path): key_store_provision failed\n");
            ok = 0;
        } else {
            status = secure_frame_verify_and_decrypt(wire, wire_len, addr, DIR_SLAVE_TO_MASTER,
                                                       &out_addr, NULL, out_pdu, &out_pdu_len,
                                                       &crc_calc, &crc_recv);
            if (status != SECURE_FRAME_OK) {
                printf("FAIL (decrypt path): secure_frame_verify_and_decrypt returned %d "
                       "(calc %04X, recv %04X)\n", (int) status, crc_calc, crc_recv);
                ok = 0;
            } else if (out_pdu_len != sizeof(pdu) || memcmp(out_pdu, pdu, sizeof(pdu)) != 0) {
                printf("FAIL (decrypt path): recovered PDU does not match what was sent\n");
                ok = 0;
            } else {
                printf("PASS (decrypt path): hand-built frame -> secure_frame_verify_and_decrypt OK "
                       "(%u byte PDU, %u byte wire frame)\n",
                       (unsigned int) out_pdu_len, (unsigned int) wire_len);
            }
        }
    }

    if (ok) {
        printf("Self-test: ALL PASS\n");
    }
}

static void do_env_config(void)
{
    char line[64];

    printf("Serial port (blank = keep current, '-' = none/file fallback) [current: %s]: ",
           config_port[0] ? config_port : "(none)");
    if (fgets(line, sizeof(line), stdin) != NULL) {
        line[strcspn(line, "\r\n")] = '\0';
        if (strcmp(line, "-") == 0) {
            config_port[0] = '\0';
        } else if (line[0] != '\0') {
            strncpy(config_port, line, sizeof(config_port) - 1);
            config_port[sizeof(config_port) - 1] = '\0';
        }
    }

    printf("Baud rate [current: %ld]: ", config_baud);
    if (fgets(line, sizeof(line), stdin) != NULL) {
        line[strcspn(line, "\r\n")] = '\0';
        if (line[0] != '\0') {
            config_baud = strtol(line, NULL, 10);
        }
    }

    printf("Slave address 1-247 (target to send to as master / our own address as slave) [current: %u]: ",
           (unsigned int) config_slave_addr);
    if (fgets(line, sizeof(line), stdin) != NULL) {
        line[strcspn(line, "\r\n")] = '\0';
        if (line[0] != '\0') {
            long v = strtol(line, NULL, 10);
            if (v >= 1 && v <= 247) {
                config_slave_addr = (uint8_t) v;
            } else {
                printf("Out of range, keeping %u\n", (unsigned int) config_slave_addr);
            }
        }
    }

    printf("Config: port=%s baud=%ld slave_addr=%u\n",
           config_port[0] ? config_port : "(none, file fallback)", config_baud,
           (unsigned int) config_slave_addr);
}

int main(int argc, char **argv)
{
    (void) argc;
    g_argv0 = argv[0];

    while (1) {
        printf("----------------------------\n");
        printf("[%s] mode, keys: %s, port: %s, slave addr: %u\n",
               is_master ? "master" : "slave",
               keys_loaded ? "loaded" : "not loaded",
               config_port[0] ? config_port : "(none)",
               (unsigned int) config_slave_addr);
        printf("1. 마스터/슬레이브 모드 전환\n");
        printf("2. 키 초기화\n");
        printf("3. 단위 테스트\n");
        printf("4. 환경 설정 \n");
        printf("5. 실행 (보안 통신 1회 수행)\n");
        printf("6. 종료\n");
        printf("----------------------------\n");

        int input;
        if (scanf("%d", &input) != 1) {
            flush_stdin_line();
            printf("올바르지 않은 입력입니다.\n");
            continue;
        }
        flush_stdin_line();

        switch (input) {
            case 1:
                is_master = !is_master;
                break;
            case 2:
                do_key_init();
                break;
            case 3:
                do_self_test();
                break;
            case 4:
                do_env_config();
                break;
            case 5:
                do_run_exchange();
                break;
            case 6:
                printf("종료합니다.\n");
                return 0;
            default:
                printf("올바르지 않은 입력입니다.\n");
        }
    }
    return 0;
}
