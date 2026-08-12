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

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int is_master = 1;

static char config_port[64] = "";      /* 비어있으면 포트 없이 파일로 폴백 */
static long config_baud = 115200;
static uint8_t config_slave_addr = 0x01;
static int keys_loaded = 0;

static void flush_stdin_line(void)
{
    int c;
    while ((c = getchar()) != '\n' && c != EOF) {
    }
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

/* T3.5 유휴 간격 (min 20ms) */
#define MODBUS_T35_MIN_GAP_US 20000
static long modbus_t35_us(long baud)
{
    long t35 = (baud > 19200) ? 1750 : (long) (3.5 * 11.0 * 1000000.0 / (double) baud);
    return (t35 > MODBUS_T35_MIN_GAP_US) ? t35 : MODBUS_T35_MIN_GAP_US;
}

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
    /* keymgmt/keys.txt is the only copy that exists now (bin/'s duplicate was
       removed) -- these paths cover running the binary from the security/
       repo root (where the Makefile actually builds it), from one level
       above it, or from a subdirectory like demo/. */
    int loaded = key_store_load_file("keys.txt");
    if (loaded <= 0) {
        loaded = key_store_load_file("keymgmt/keys.txt");
    }
    if (loaded <= 0) {
        loaded = key_store_load_file("security/keymgmt/keys.txt");
    }
    if (loaded <= 0) {
        loaded = key_store_load_file("../keymgmt/keys.txt");
    }
    if (loaded <= 0) {
        printf("Could not load keys.txt (tried cwd, keymgmt/keys.txt, security/keymgmt/keys.txt, ../keymgmt/keys.txt)\n");
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
    secure_frame_t frame;
    directional_keys_t keys;
    uint8_t mac_input[SECURE_FRAME_ADDR_LEN + SECURE_FRAME_MAX_ADU];
    uint8_t expected_hmac[HMAC_LSH_FULL_SIZE];
    lea_key_schedule_t ks;
    uint8_t ctr_high[LEA_CTR_HIGH_SIZE];
    uint32_t ctr_low;
    uint8_t plaintext_adu[SECURE_FRAME_MAX_ADU];
    uint16_t crc_calc, crc_recv;

    if (!secure_frame_parse(rx_buf, rx_len, &frame)) {
        printf("Malformed frame (%u bytes, too short for addr+hmac)\n", (unsigned int) rx_len);
        return;
    }
    printf("Parsed: addr=%u ciphertext_len=%u\n", (unsigned int) frame.addr, (unsigned int) frame.ciphertext_len);

    /* 실제 RS-485 버스에는 슬레이브가 여럿 달릴 수 있어 이 프레임이 우리 주소로 온 게 아닐 수
       있음 -- 그런 프레임은 (키가 있어도) 우리 것으로 처리하면 안 되므로 여기서 걸러냄. */
    if (frame.addr != config_slave_addr) {
        printf("Frame addressed to slave %u, not us (configured as %u) -- ignoring\n",
               (unsigned int) frame.addr, (unsigned int) config_slave_addr);
        return;
    }

    if (key_store_lookup(frame.addr, DIR_MASTER_TO_SLAVE, &keys) != 0) {
        printf("No m2s key provisioned for slave %u\n", (unsigned int) frame.addr);
        return;
    }

    mac_input[0] = frame.addr;
    memcpy(mac_input + SECURE_FRAME_ADDR_LEN, frame.ciphertext, frame.ciphertext_len);
    hmac_lsh256(keys.mac_key, KEY_SIZE, mac_input, SECURE_FRAME_ADDR_LEN + frame.ciphertext_len, expected_hmac);
    if (memcmp(expected_hmac, frame.hmac, SECURE_FRAME_HMAC_LEN) != 0) {
        printf("HMAC MISMATCH -- frame rejected\n");
        return;
    }
    printf("HMAC OK\n");

    memset(ctr_high, 0, sizeof(ctr_high));
    ctr_low = ctr_state_next_outgoing(frame.addr, DIR_MASTER_TO_SLAVE, frame.ciphertext_len);
    lea_key_schedule(keys.enc_key, &ks);
    lea_ctr_crypt(&ks, ctr_high, ctr_low, 0, frame.ciphertext, plaintext_adu, frame.ciphertext_len);

    if (frame.ciphertext_len < SECURE_FRAME_CRC_LEN) {
        printf("Decrypted ADU too short to hold a CRC\n");
        return;
    }
    crc_calc = modbus_crc16(plaintext_adu, frame.ciphertext_len - SECURE_FRAME_CRC_LEN);
    crc_recv = (uint16_t) plaintext_adu[frame.ciphertext_len - 2] |
               ((uint16_t) plaintext_adu[frame.ciphertext_len - 1] << 8);
    if (crc_calc != crc_recv) {
        printf("CRC MISMATCH (calc %04X, recv %04X) -- wrong counter sync?\n", crc_calc, crc_recv);
        return;
    }
    printf("CRC OK\n");
    print_hex("Recovered PDU", plaintext_adu + SECURE_FRAME_ADDR_LEN,
               frame.ciphertext_len - SECURE_FRAME_ADDR_LEN - SECURE_FRAME_CRC_LEN);

    if (sp != NULL && frame.ciphertext_len >= SECURE_FRAME_ADDR_LEN + 5 + SECURE_FRAME_CRC_LEN) {
        uint8_t reply_pdu[5];
        uint8_t reply_wire[SECURE_FRAME_MAX_WIRE_LEN];
        size_t reply_wire_len;

        memcpy(reply_pdu, plaintext_adu + SECURE_FRAME_ADDR_LEN, sizeof(reply_pdu));
        if (secure_frame_encrypt_and_build(frame.addr, reply_pdu, sizeof(reply_pdu),
                                            DIR_SLAVE_TO_MASTER, reply_wire, &reply_wire_len) != 0) {
            printf("Reply encrypt failed -- no s2m key for slave %u\n", (unsigned int) frame.addr);
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
        secure_frame_t reply;
        directional_keys_t keys;
        uint8_t mac_input[SECURE_FRAME_ADDR_LEN + SECURE_FRAME_MAX_ADU];
        uint8_t expected_hmac[HMAC_LSH_FULL_SIZE];
        lea_key_schedule_t ks;
        uint8_t ctr_high[LEA_CTR_HIGH_SIZE];
        uint32_t ctr_low;
        uint8_t plaintext_adu[SECURE_FRAME_MAX_ADU];
        uint16_t crc_calc, crc_recv;

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

        if (!secure_frame_parse(rx_buf, rx_len, &reply)) {
            printf("Malformed reply frame\n");
            return;
        }
        if (reply.addr != config_slave_addr) {
            printf("Reply addr mismatch (expected %u, got %u)\n",
                   (unsigned int) config_slave_addr, (unsigned int) reply.addr);
            return;
        }
        if (key_store_lookup(config_slave_addr, DIR_SLAVE_TO_MASTER, &keys) != 0) {
            printf("No s2m key provisioned for slave %u\n", (unsigned int) config_slave_addr);
            return;
        }

        mac_input[0] = reply.addr;
        memcpy(mac_input + SECURE_FRAME_ADDR_LEN, reply.ciphertext, reply.ciphertext_len);
        hmac_lsh256(keys.mac_key, KEY_SIZE, mac_input,
                    SECURE_FRAME_ADDR_LEN + reply.ciphertext_len, expected_hmac);
        if (memcmp(expected_hmac, reply.hmac, SECURE_FRAME_HMAC_LEN) != 0) {
            printf("Reply HMAC MISMATCH\n");
            return;
        }
        printf("Reply HMAC OK\n");

        memset(ctr_high, 0, sizeof(ctr_high));
        ctr_low = ctr_state_next_outgoing(config_slave_addr, DIR_SLAVE_TO_MASTER, reply.ciphertext_len);
        lea_key_schedule(keys.enc_key, &ks);
        lea_ctr_crypt(&ks, ctr_high, ctr_low, 0, reply.ciphertext, plaintext_adu, reply.ciphertext_len);

        if (reply.ciphertext_len < SECURE_FRAME_CRC_LEN) {
            printf("Decrypted reply too short to hold a CRC\n");
            return;
        }
        crc_calc = modbus_crc16(plaintext_adu, reply.ciphertext_len - SECURE_FRAME_CRC_LEN);
        crc_recv = (uint16_t) plaintext_adu[reply.ciphertext_len - 2] |
                   ((uint16_t) plaintext_adu[reply.ciphertext_len - 1] << 8);
        if (crc_calc != crc_recv) {
            printf("Reply CRC MISMATCH (calc %04X, recv %04X)\n", crc_calc, crc_recv);
            return;
        }
        printf("Reply CRC OK\n");
        print_hex("Recovered reply PDU", plaintext_adu + SECURE_FRAME_ADDR_LEN,
                   reply.ciphertext_len - SECURE_FRAME_ADDR_LEN - SECURE_FRAME_CRC_LEN);
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

/* encrypt -> build -> parse -> HMAC 검증 -> LEA-CTR 복호화 -> CRC 검증까지 왕복 전 구간을
   한 프로세스 안에서 실행해보는 암호화 로직 점검용 테스트. serial_port를 전혀 거치지 않으므로
   이 테스트가 통과해도 실제 RS-485 배선/포트(/dev/ttyAMA0, COM 포트 등) 상태는 확인 X.
  하드웨어/배선 확인은 옵션 4로 포트를 설정한 뒤 옵션 5(실행)로 해야 한다.
 */
static void do_self_test(void)
{
    const uint8_t test_addr = 0xF0;
    uint8_t enc_key[KEY_SIZE], mac_key[KEY_SIZE];
    uint8_t plaintext_pdu[5] = {0x03, 0x00, 0x00, 0x00, 0x02}; /* read holding registers, addr 0, qty 2 */
    uint8_t plaintext_adu_in[SECURE_FRAME_MAX_ADU];
    size_t adu_len;
    uint16_t crc;
    secure_frame_t frame;
    uint8_t wire[SECURE_FRAME_MAX_WIRE_LEN];
    size_t wire_len;
    secure_frame_t parsed;
    uint8_t mac_input[SECURE_FRAME_ADDR_LEN + SECURE_FRAME_MAX_ADU];
    uint8_t expected_hmac[HMAC_LSH_FULL_SIZE];
    lea_key_schedule_t ks;
    uint8_t ctr_high[LEA_CTR_HIGH_SIZE];
    uint8_t plaintext_adu[SECURE_FRAME_MAX_ADU];
    uint16_t crc_calc, crc_recv;
    int i;

    printf("Running crypto logic self-test (no serial port involved)...\n");

    for (i = 0; i < KEY_SIZE; i++) {
        enc_key[i] = (uint8_t) (0x10 + i);
        mac_key[i] = (uint8_t) (0x20 + i);
    }
    memset(ctr_high, 0, sizeof(ctr_high));

    plaintext_adu_in[0] = test_addr;
    memcpy(plaintext_adu_in + SECURE_FRAME_ADDR_LEN, plaintext_pdu, sizeof(plaintext_pdu));
    crc = modbus_crc16(plaintext_adu_in, SECURE_FRAME_ADDR_LEN + sizeof(plaintext_pdu));
    plaintext_adu_in[SECURE_FRAME_ADDR_LEN + sizeof(plaintext_pdu)] = (uint8_t) (crc & 0xFF);
    plaintext_adu_in[SECURE_FRAME_ADDR_LEN + sizeof(plaintext_pdu) + 1] = (uint8_t) (crc >> 8);
    adu_len = SECURE_FRAME_ADDR_LEN + sizeof(plaintext_pdu) + SECURE_FRAME_CRC_LEN;

    frame.addr = test_addr;
    frame.ciphertext_len = adu_len;
    lea_key_schedule(enc_key, &ks);
    lea_ctr_crypt(&ks, ctr_high, 0, 1, plaintext_adu_in, frame.ciphertext, adu_len);

    mac_input[0] = frame.addr;
    memcpy(mac_input + SECURE_FRAME_ADDR_LEN, frame.ciphertext, adu_len);
    hmac_lsh256(mac_key, KEY_SIZE, mac_input, SECURE_FRAME_ADDR_LEN + adu_len, frame.hmac);

    wire_len = secure_frame_build(&frame, wire);

    if (!secure_frame_parse(wire, wire_len, &parsed)) {
        printf("FAIL: secure_frame_parse rejected the frame it just built\n");
        return;
    }

    mac_input[0] = parsed.addr;
    memcpy(mac_input + SECURE_FRAME_ADDR_LEN, parsed.ciphertext, parsed.ciphertext_len);
    hmac_lsh256(mac_key, KEY_SIZE, mac_input, SECURE_FRAME_ADDR_LEN + parsed.ciphertext_len, expected_hmac);
    if (memcmp(expected_hmac, parsed.hmac, SECURE_FRAME_HMAC_LEN) != 0) {
        printf("FAIL: HMAC mismatch\n");
        return;
    }

    lea_ctr_crypt(&ks, ctr_high, 0, 0, parsed.ciphertext, plaintext_adu, parsed.ciphertext_len);

    crc_calc = modbus_crc16(plaintext_adu, parsed.ciphertext_len - SECURE_FRAME_CRC_LEN);
    crc_recv = (uint16_t) plaintext_adu[parsed.ciphertext_len - 2] |
               ((uint16_t) plaintext_adu[parsed.ciphertext_len - 1] << 8);
    if (crc_calc != crc_recv) {
        printf("FAIL: CRC mismatch after decrypt (calc %04X, recv %04X)\n", crc_calc, crc_recv);
        return;
    }

    if (plaintext_adu[0] != test_addr ||
        memcmp(plaintext_adu + SECURE_FRAME_ADDR_LEN, plaintext_pdu, sizeof(plaintext_pdu)) != 0) {
        printf("FAIL: recovered PDU does not match what was sent\n");
        return;
    }

    printf("PASS: encrypt -> parse -> HMAC verify -> decrypt -> CRC check round-trip OK "
           "(%u byte PDU, %u byte wire frame)\n",
           (unsigned int) sizeof(plaintext_pdu), (unsigned int) wire_len);
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

int main(void) {

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
