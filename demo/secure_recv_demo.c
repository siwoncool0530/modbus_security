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
#include "../crypto/lea.h"
#include "../crypto/lea_ctr.h"
#include "../crypto/hmac_lsh.h"
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include "serial_port.h"

#define DEFAULT_BAUD 9600

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

/* Modbus RTU 스펙의 T3.5 유휴 간격(이 이상 침묵하면 프레임 경계로 간주)을
   마이크로초 단위로 계산. 19200 baud 초과에서는 스펙이 고정 1750us를 규정하고,
   그 이하에서는 3.5 캐릭터 타임 (스펙이 가정하는 11비트 캐릭터: start+8data+parity+stop
   기준 -- 현재 로컬 UART 설정은 8N1).

   MIN_GAP_US: CM5의 실제 UART로 9600/19200/38400/57600 baud에서 순수 스펙값(1.7~4ms)이
   매번 프레임을 16/16/12바이트로 조기에 절단시키는 것을 실측 확인 (T3.5 값 자체를 baud별로 바꿔가며 재현해도 절단 지점이 동일
   - 회선 타이밍이 아니라 커널/드라이버 쪽 고정 지연이 원인). 이분 탐색으로 16ms에서 실패, 17ms에서 성공하는 정확한 경계를 확인
   - 여유를 두고 20ms로 최소값을 둠.
   115200 baud는 이 바닥이 없어도(순수 스펙값 334us로도) 항상 성공했으므로 이 최소값은 그 경우엔 그냥 더 보수적인 값. */
#define MODBUS_T35_MIN_GAP_US 20000
static long modbus_t35_us(long baud)
{
    long t35 = (baud > 19200) ? 1750 : (long) (3.5 * 11.0 * 1000000.0 / (double) baud);
    return (t35 > MODBUS_T35_MIN_GAP_US) ? t35 : MODBUS_T35_MIN_GAP_US;
}

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

    return key_store_load_file("security/keymgmt/keys.txt");
}

/* 프레임 하나를 수신하여 검증하고 복호화한다. 반환 코드:
     0 - 성공 (HMAC과 CRC 모두 정상)
    -1 - 프레임은 도착했지만 거부됨 (형식 오류/HMAC/CRC) -- 다음 프레임 시도
     1 - 타임아웃, 아무것도 도착하지 않음 -- 실행 종료
     2 - 포트에서 I/O 오류 발생 -- 실행 종료 */
static int receive_one_frame(serial_port_t *sp)
{
    uint8_t rx_buf[SECURE_FRAME_MAX_WIRE_LEN];
    long rx_len;
    secure_frame_t frame;
    directional_keys_t keys;
    uint8_t mac_input[SECURE_FRAME_ADDR_LEN + SECURE_FRAME_MAX_ADU];
    uint8_t expected_hmac[HMAC_LSH_FULL_SIZE];
    lea_key_schedule_t ks;
    uint8_t ctr_high[LEA_CTR_HIGH_SIZE];
    uint32_t ctr_low;
    uint8_t plaintext_adu[SECURE_FRAME_MAX_ADU];
    uint16_t crc_calc, crc_recv;

    rx_len = serial_port_read(sp, rx_buf, sizeof(rx_buf));
    if (rx_len < 0) {
        return 2;
    }
    if (rx_len == 0) {
        log_detail("Timed out -- no frame received\n");
        return 1;
    }

    print_hex("Received raw frame", rx_buf, rx_len);

    if (!secure_frame_parse(rx_buf, rx_len, &frame)) {
        log_detail("secure_frame_parse: malformed frame (%u bytes, too short "
                   "for addr+hmac)\n",
                   (unsigned int) rx_len);
        serial_port_drain(sp);
        return -1;
    }
    log_detail("Parsed: addr=%u ciphertext_len=%u\n",
               (unsigned int) frame.addr,
               (unsigned int) frame.ciphertext_len);

    if (key_store_lookup(frame.addr, DIR_MASTER_TO_SLAVE, &keys) != 0) {
        log_detail("No key provisioned for slave %u\n", (unsigned int) frame.addr);
        serial_port_drain(sp);
        return -1;
    }

    mac_input[0] = frame.addr;
    memcpy(mac_input + SECURE_FRAME_ADDR_LEN, frame.ciphertext, frame.ciphertext_len);
    hmac_lsh256(keys.mac_key,
                KEY_SIZE,
                mac_input,
                SECURE_FRAME_ADDR_LEN + frame.ciphertext_len,
                expected_hmac);

    if (memcmp(expected_hmac, frame.hmac, SECURE_FRAME_HMAC_LEN) != 0) {
        print_hex("Expected HMAC", expected_hmac, SECURE_FRAME_HMAC_LEN);
        print_hex("Received HMAC", frame.hmac, SECURE_FRAME_HMAC_LEN);
        log_detail("HMAC MISMATCH -- frame rejected\n");
        serial_port_drain(sp);
        return -1;
    }
    log_detail("HMAC OK\n");

    memset(ctr_high, 0, sizeof(ctr_high));
    ctr_low = ctr_state_next_outgoing(frame.addr, DIR_MASTER_TO_SLAVE, frame.ciphertext_len);
    log_detail("Decrypting with ctr_high=%02X%02X%02X%02X, ctr_low=%08X\n",
               ctr_high[0], ctr_high[1], ctr_high[2], ctr_high[3], ctr_low);

    lea_key_schedule(keys.enc_key, &ks);
    lea_ctr_crypt(&ks, ctr_high, ctr_low, 0, frame.ciphertext, plaintext_adu, frame.ciphertext_len);
    print_hex("Decrypted ADU [addr|pdu|crc16]", plaintext_adu, frame.ciphertext_len);

    if (frame.ciphertext_len < SECURE_FRAME_CRC_LEN) {
        log_detail("Decrypted ADU too short to hold a CRC\n");
        serial_port_drain(sp);
        return -1;
    }
    crc_calc = modbus_crc16(plaintext_adu, frame.ciphertext_len - SECURE_FRAME_CRC_LEN);
    crc_recv = (uint16_t) plaintext_adu[frame.ciphertext_len - 2] |
               ((uint16_t) plaintext_adu[frame.ciphertext_len - 1] << 8);
    if (crc_calc != crc_recv) {
        log_detail("CRC MISMATCH (calc %04X, recv %04X) -- wrong counter sync?\n",
                   crc_calc,
                   crc_recv);
        serial_port_drain(sp);
        return -1;
    }
    log_detail("CRC OK\n");

    print_hex("Recovered PDU", plaintext_adu + SECURE_FRAME_ADDR_LEN,
               frame.ciphertext_len - SECURE_FRAME_ADDR_LEN - SECURE_FRAME_CRC_LEN);

    /* 요청을 검증/복호화했으니 슬레이브 입장에서 응답까지 회신 -- 실제 Modbus 0x10(Write
       Multiple Registers)의 응답 형식은 함수코드+시작주소(2)+수량(2), 총 5바이트이며
       요청 PDU의 앞 5바이트를 그대로 반사한 값과 동일함 (실제 레지스터 저장소가 없는
       데모이므로 진짜로 "적었다"고 답하는 대신 요청을 그대로 반사). DIR_SLAVE_TO_MASTER
       방향 키로 암호화해 같은 포트로 회신 -- 이제야 s2m 방향이 실제로 사용됨.
       ciphertext_len이 5바이트 프리픽스보다 짧은 비정상 요청이면(함수코드가 다르거나
       손상된 경우) 반사하지 않고 건너뜀. */
    if (frame.ciphertext_len >= SECURE_FRAME_ADDR_LEN + 5 + SECURE_FRAME_CRC_LEN) {
        uint8_t reply_pdu[5];
        uint8_t reply_wire[SECURE_FRAME_MAX_WIRE_LEN];
        size_t reply_wire_len;

        memcpy(reply_pdu, plaintext_adu + SECURE_FRAME_ADDR_LEN, sizeof(reply_pdu));

        if (secure_frame_encrypt_and_build(frame.addr,
                                            reply_pdu,
                                            sizeof(reply_pdu),
                                            DIR_SLAVE_TO_MASTER,
                                            reply_wire,
                                            &reply_wire_len) != 0) {
            log_detail("reply: encrypt failed (no s2m key for slave %u?)\n", (unsigned int) frame.addr);
        } else if (serial_port_write(sp, reply_wire, reply_wire_len) != 0) {
            log_detail("reply: write failed\n");
        } else {
            print_hex("Sent reply wire frame", reply_wire, reply_wire_len);
            log_detail("Reply sent (%u bytes)\n", (unsigned int) reply_wire_len);
        }
    } else {
        log_detail("Request PDU too short for a reply prefix (%u bytes) -- skipping reply\n",
                   (unsigned int) frame.ciphertext_len);
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

    loaded = load_keys(argv[0]);
    if (loaded <= 0) {
        log_summary("Could not load keys.txt (tried cwd, next to the "
                     "executable, and security/keymgmt/keys.txt)\n");
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