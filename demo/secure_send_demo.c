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
#include "../crypto/lea.h"
#include "../crypto/lea_ctr.h"
#include "../crypto/hmac_lsh.h"
#include "serial_port.h"
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>

#define DEFAULT_BAUD 115200

/* log_detail()은 g_log 파일에만 기록.
    log_summary()는 g_log 파일과 console 양쪽에 기록되며, 프레임당 한 줄의 결과를 보여줌.
 */
static FILE *g_log = NULL;

static void log_open(const char *path)
{
    g_log = fopen(path, "w");
    if (g_log == NULL) {
        fprintf(stderr, "Warning: could not open log file %s -- continuing without one\n", path);
    }
}

static void log_close_atexit(void)
{
    if (g_log != NULL) {
        fclose(g_log);
        g_log = NULL;
    }
}

/* 전체 상세 정보(PDU/회선 프레임 16진수 덤프, 전송별 진단 정보) - g_log 파일에만 기록.
    크기가 제각각인 여러 프레임을 한 번에 실행하면 터미널에서 실시간으로 읽기엔 양이 너무 많으므로,
    특정 프레임을 나중에 살펴봐야 할 때를 위해 send_log.txt에 보관. */
static void log_detail(const char *fmt, ...)
{
    va_list ap;

    if (g_log != NULL) {
        va_start(ap, fmt);
        vfprintf(g_log, fmt, ap);
        va_end(ap);
        fflush(g_log); /* 중도 중단될 경우 대비 */
    }
}

/* 프레임당 한 줄로 결과 및 성공/실패 요약 메시지 */
static void log_summary(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);

    if (g_log != NULL) {
        va_start(ap, fmt);
        vfprintf(g_log, fmt, ap);
        va_end(ap);
        fflush(g_log);
    }
}

static void print_hex(const char *label, const uint8_t *buf, size_t len)
{
    size_t i;
    log_detail("%s (%u bytes): ", label, (unsigned int) len);
    for (i = 0; i < len; i++) {
        log_detail("%02X ", buf[i]);
    }
    log_detail("\n");
}

/* secure_recv_demo.c의 modbus_crc16()과 동일. 회신을 복호화한 뒤 CRC를
   검증하는 데 사용 (요청 측과 동일한 표준 Modbus CRC16). */
static uint16_t modbus_crc16(const uint8_t *buf, size_t len)
{
    uint16_t crc = 0xFFFF;
    size_t i;
    int bit;

    for (i = 0; i < len; i++) {
        crc ^= buf[i];
        for (bit = 0; bit < 8; bit++) {
            crc = (crc & 1) ? (uint16_t) ((crc >> 1) ^ 0xA001) : (uint16_t) (crc >> 1);
        }
    }
    return crc;
}

/* secure_recv_demo.c의 modbus_t35_us()와 동일한 공식 -- 수신측이 실제로
   프레임 경계로 요구하는 유휴 간격을 그대로 재사용해 프레임 간 대기시간을
   산정하기 위함 (두 파일 사이에 값이 어긋나면 다시 같은 문제가 재발할 수
   있으므로 반드시 동일하게 유지). 안전 여유로 2배를 곱해 실제 대기시간으로
   씀 -- 프레임을 하나씩 순서대로 보내기만 하므로 여유를 더 둬도 손해가
   없음. 20ms 바닥값의 근거는 실측: 9600/19200/38400/57600 baud에서
   16ms=실패, 17ms=성공의 정확한 경계를 이분 탐색으로 확인함(원인은 커널/
   드라이버 쪽 고정 지연으로 추정, baud와 무관). */
#define MODBUS_T35_MIN_GAP_US 20000
static long modbus_t35_us(long baud)
{
    long t35 = (baud > 19200) ? 1750 : (long) (3.5 * 11.0 * 1000000.0 / (double) baud);
    return (t35 > MODBUS_T35_MIN_GAP_US) ? t35 : MODBUS_T35_MIN_GAP_US;
}

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
    secure_frame_t reply;
    directional_keys_t keys;
    uint8_t mac_input[SECURE_FRAME_ADDR_LEN + SECURE_FRAME_MAX_ADU];
    uint8_t expected_hmac[HMAC_LSH_FULL_SIZE];
    lea_key_schedule_t ks;
    uint8_t ctr_high[LEA_CTR_HIGH_SIZE];
    uint32_t ctr_low;
    uint8_t plaintext_adu[SECURE_FRAME_MAX_ADU];
    uint16_t crc_calc, crc_recv;

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

    if (!secure_frame_parse(rx_buf, rx_len, &reply)) {
        log_detail("reply: malformed frame (%u bytes, too short for addr+hmac)\n", (unsigned int) rx_len);
        return -1;
    }
    if (reply.addr != slave_addr) {
        log_detail("reply: addr mismatch (expected %u, got %u)\n",
                   (unsigned int) slave_addr,
                   (unsigned int) reply.addr);
        return -1;
    }
    if (key_store_lookup(slave_addr, DIR_SLAVE_TO_MASTER, &keys) != 0) {
        log_detail("reply: no s2m key provisioned for slave %u\n", (unsigned int) slave_addr);
        return -1;
    }

    mac_input[0] = reply.addr;
    memcpy(mac_input + SECURE_FRAME_ADDR_LEN, reply.ciphertext, reply.ciphertext_len);
    hmac_lsh256(keys.mac_key,
                KEY_SIZE,
                mac_input,
                SECURE_FRAME_ADDR_LEN + reply.ciphertext_len,
                expected_hmac);
    if (memcmp(expected_hmac, reply.hmac, SECURE_FRAME_HMAC_LEN) != 0) {
        print_hex("Expected reply HMAC", expected_hmac, SECURE_FRAME_HMAC_LEN);
        print_hex("Received reply HMAC", reply.hmac, SECURE_FRAME_HMAC_LEN);
        log_detail("reply: HMAC MISMATCH\n");
        return -1;
    }
    log_detail("reply: HMAC OK\n");

    memset(ctr_high, 0, sizeof(ctr_high));
    ctr_low = ctr_state_next_outgoing(slave_addr, DIR_SLAVE_TO_MASTER, reply.ciphertext_len);
    log_detail("Decrypting reply with ctr_high=%02X%02X%02X%02X, ctr_low=%08X\n",
               ctr_high[0], ctr_high[1], ctr_high[2], ctr_high[3], ctr_low);

    lea_key_schedule(keys.enc_key, &ks);
    lea_ctr_crypt(&ks, ctr_high, ctr_low, 0, reply.ciphertext, plaintext_adu, reply.ciphertext_len);
    print_hex("Decrypted reply ADU", plaintext_adu, reply.ciphertext_len);

    if (reply.ciphertext_len < SECURE_FRAME_CRC_LEN) {
        log_detail("reply: decrypted ADU too short to hold a CRC\n");
        return -1;
    }
    crc_calc = modbus_crc16(plaintext_adu, reply.ciphertext_len - SECURE_FRAME_CRC_LEN);
    crc_recv = (uint16_t) plaintext_adu[reply.ciphertext_len - 2] |
               ((uint16_t) plaintext_adu[reply.ciphertext_len - 1] << 8);
    if (crc_calc != crc_recv) {
        log_detail("reply: CRC MISMATCH (calc %04X, recv %04X)\n", crc_calc, crc_recv);
        return -1;
    }
    log_detail("reply: CRC OK\n");

    print_hex("Recovered reply PDU", plaintext_adu + SECURE_FRAME_ADDR_LEN,
               reply.ciphertext_len - SECURE_FRAME_ADDR_LEN - SECURE_FRAME_CRC_LEN);

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

/* "<argv0을 담고 있는 디렉터리>/filename" 형태의 문자열을 out에 만들어 넣음.
   argv0에 디렉터리 구성요소가 없으면 그냥 filename으로 대체.
   keys.txt, CTR 카운터 파일을 실행 파일 위치에 고정하는 데 사용.
   잘못된 ctr_state 파일을 읽고 쓰면 송신자/수신자 카운터 어긋나므로 유의. (카운터 전송하지 않으므로) */
static void exe_relative_path(const char *argv0, const char *filename, char *out, size_t out_size)
{
    const char *slash = strrchr(argv0, '/');
#ifdef _WIN32
    const char *backslash = strrchr(argv0, '\\');
    if (backslash != NULL && (slash == NULL || backslash > slash)) {
        slash = backslash;
    }
#endif

    if (slash != NULL) {
        size_t dir_len = (size_t) (slash - argv0) + 1;
        if (dir_len + strlen(filename) < out_size) {
            memcpy(out, argv0, dir_len);
            strcpy(out + dir_len, filename);
            return;
        }
    }
    strncpy(out, filename, out_size - 1);
    out[out_size - 1] = '\0';
}

// 파일로부터 키를 가져옴. binary가 존재하는 위치에 없을 경우 argv0 경로를, 마지막으로 개발 트리 경로를 시도.
static int load_keys(const char *argv0)
{
    char exe_relative[512];
    int loaded = key_store_load_file("keys.txt");
    if (loaded > 0) {
        return loaded;
    }

    exe_relative_path(argv0, "keys.txt", exe_relative, sizeof(exe_relative));
    loaded = key_store_load_file(exe_relative);
    if (loaded > 0) {
        return loaded;
    }

    loaded = key_store_load_file("keymgmt/keys.txt");
    if (loaded > 0) {
        return loaded;
    }

    return key_store_load_file("security/keymgmt/keys.txt");
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

    loaded = load_keys(argv[0]);
    if (loaded <= 0) {
        log_summary("Could not load keys.txt (tried cwd, next to the "
                     "executable, keymgmt/keys.txt, and security/keymgmt/keys.txt)\n");
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