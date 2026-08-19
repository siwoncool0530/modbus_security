/* modbus_pdu_selftest.h 참고. 테이블 초기값은 modbus_pdu.c의 ensure_table_initialized()와
   동일: holding_registers[i] = 0x1000+i, input_registers[i] = 0x2000+i, coils[i] = i%2,
   discrete_inputs[i] = (i+1)%2.
   이 함수는 같은 프로세스에서 여러 번 불릴 수 있음(main.c 옵션 3을 반복 선택)
    */
#include "modbus_pdu.h"
#include "modbus_pdu_selftest.h"
#include <stdio.h>
#include <string.h>

static int g_pass;
static int g_fail;

static void report(const char *name, int ok, const char *detail)
{
    if (ok) {
        g_pass++;
        printf("[PASS] %s\n", name);
    } else {
        g_fail++;
        printf("[FAIL] %s -- %s\n", name, detail ? detail : "?");
    }
}

/* rc==1이고 응답이 exp[0..exp_len)과 정확히 일치해야 통과 */
static void check_exact(const char *name, const uint8_t *req, size_t req_len,
                         const uint8_t *exp, size_t exp_len)
{
    uint8_t resp[300];
    size_t resp_len = 0;
    int rc = modbus_build_response(req, req_len, resp, &resp_len);
    char detail[64];

    if (!rc) {
        report(name, 0, "modbus_build_response() returned 0");
        return;
    }
    if (resp_len != exp_len) {
        snprintf(detail, sizeof(detail), "resp_len=%zu, expected %zu", resp_len, exp_len);
        report(name, 0, detail);
        return;
    }
    if (memcmp(resp, exp, exp_len) != 0) {
        report(name, 0, "byte mismatch");
        return;
    }
    report(name, 1, NULL);
}

/* 예외 응답(func|0x80, exc_code, 길이 2)만 검증 */
static void check_exception(const char *name, const uint8_t *req, size_t req_len,
                             uint8_t func, uint8_t exc_code)
{
    uint8_t exp[2];
    exp[0] = (uint8_t) (func | MODBUS_EXCEPTION_BIT);
    exp[1] = exc_code;
    check_exact(name, req, req_len, exp, sizeof(exp));
}

int modbus_pdu_self_test(void)
{
    g_pass = 0;
    g_fail = 0;

    /* ---- 1~4: 8개 Function Codes 중 4개 읽기 함수의 성공 경로 (addr 0, qty 2) ---- */
    {
        uint8_t req[] = {0x01, 0x00, 0x00, 0x00, 0x02};
        uint8_t exp[] = {0x01, 0x01, 0x02}; /* coil0=0,coil1=1 -> bit0=0,bit1=1 */
        check_exact("0x01 Read Coils success", req, sizeof(req), exp, sizeof(exp));
    }
    {
        uint8_t req[] = {0x02, 0x00, 0x00, 0x00, 0x02};
        uint8_t exp[] = {0x02, 0x01, 0x01}; /* d0=1,d1=0 -> bit0=1,bit1=0 */
        check_exact("0x02 Read Discrete Inputs success", req, sizeof(req), exp, sizeof(exp));
    }
    {
        uint8_t req[] = {0x03, 0x00, 0x00, 0x00, 0x02};
        uint8_t exp[] = {0x03, 0x04, 0x10, 0x00, 0x10, 0x01};
        check_exact("0x03 Read Holding Registers success", req, sizeof(req), exp, sizeof(exp));
    }
    {
        uint8_t req[] = {0x04, 0x00, 0x00, 0x00, 0x02};
        uint8_t exp[] = {0x04, 0x04, 0x20, 0x00, 0x20, 0x01};
        check_exact("0x04 Read Input Registers success", req, sizeof(req), exp, sizeof(exp));
    }

    /* ---- 5~6: 테이블 크기(128) 경계 -- addr+qty==128은 성공, ==129는 Illegal Data Address ---- */
    {
        uint8_t req[] = {0x01, 0x00, 0x7E, 0x00, 0x02}; /* addr=126, qty=2 -> 126+2=128 */
        uint8_t exp[] = {0x01, 0x01, 0x02}; /* coil126=0,coil127=1 */
        check_exact("boundary: addr+qty == table size (128) succeeds", req, sizeof(req), exp, sizeof(exp));
    }
    {
        uint8_t req[] = {0x01, 0x00, 0x7F, 0x00, 0x02}; /* addr=127, qty=2 -> 127+2=129 */
        check_exception("boundary: addr+qty == table size+1 (129) -> Illegal Data Address",
                         req, sizeof(req), MODBUS_FUNC_READ_COILS, MODBUS_EXCEPTION_ILLEGAL_DATA_ADDRESS);
    }

    /* ---- 7: 프로토콜 quantity 상한(레지스터 125) 자체는 유효 주소 범위 내에서 성공 ---- */
    {
        uint8_t req[] = {0x03, 0x00, 0x00, 0x00, 0x7D}; /* addr=0, qty=125 (MODBUS_MAX_READ_REGISTERS) */
        uint8_t resp[300];
        size_t resp_len = 0;
        int rc = modbus_build_response(req, sizeof(req), resp, &resp_len);
        int ok = rc && resp_len == 252 && resp[0] == 0x03 && resp[1] == 250 &&
                 resp[2] == 0x10 && resp[3] == 0x00 &&              /* reg[0]   = 0x1000 */
                 resp[250] == 0x10 && resp[251] == 0x7C;            /* reg[124] = 0x107C */
        report("boundary: qty == protocol max (125) succeeds", ok,
               ok ? NULL : "header/length/spot-check mismatch");
    }

    /* ---- 8: 프로토콜 quantity 상한 초과(126) -> Illegal Data Value ---- */
    {
        uint8_t req[] = {0x03, 0x00, 0x00, 0x00, 0x7E}; /* qty=126 > 125 */
        check_exception("boundary: qty == protocol max+1 (126) -> Illegal Data Value",
                         req, sizeof(req), MODBUS_FUNC_READ_HOLDING_REGISTERS, MODBUS_EXCEPTION_ILLEGAL_DATA_VALUE);
    }

    /* ---- 9: 요청 길이가 최소 필드 길이(5)보다 짧음 -> Illegal Data Value ---- */
    {
        uint8_t req[] = {0x03, 0x00, 0x00}; /* addr까지만 있고 qty가 없음 (len=3 < 5) */
        check_exception("boundary: req_len < 5 -> Illegal Data Value",
                         req, sizeof(req), MODBUS_FUNC_READ_HOLDING_REGISTERS, MODBUS_EXCEPTION_ILLEGAL_DATA_VALUE);
    }

    /* ---- 10: 예외 코드 1/3 -- Illegal Data Value (qty=0) ---- */
    {
        uint8_t req[] = {0x03, 0x00, 0x00, 0x00, 0x00};
        check_exception("exception: qty=0 -> Illegal Data Value",
                         req, sizeof(req), MODBUS_FUNC_READ_HOLDING_REGISTERS, MODBUS_EXCEPTION_ILLEGAL_DATA_VALUE);
    }

    /* ---- 11: 예외 코드 2/3 -- Illegal Data Address ---- */
    {
        uint8_t req[] = {0x03, 0x00, 0x7F, 0x00, 0x02}; /* addr=127, qty=2 -> 129 > 128 */
        check_exception("exception: addr+qty > table size -> Illegal Data Address",
                         req, sizeof(req), MODBUS_FUNC_READ_HOLDING_REGISTERS, MODBUS_EXCEPTION_ILLEGAL_DATA_ADDRESS);
    }

    /* ---- 12: 예외 코드 3/3 -- Illegal Function ---- */
    {
        uint8_t req[] = {0x07}; /* 8종 밖의 함수 코드 */
        check_exception("exception: unsupported function code -> Illegal Function",
                         req, sizeof(req), 0x07, MODBUS_EXCEPTION_ILLEGAL_FUNCTION);
    }

    /* ---- 13~16: 쓰기 함수의 검증 실패 경로 (테이블을 건드리지 않으므로 순서 무관) ---- */
    {
        uint8_t req[] = {0x05, 0x00, 0x00, 0x12, 0x34}; /* value가 0x0000/0xFF00이 아님 */
        check_exception("boundary: Write Single Coil invalid value -> Illegal Data Value",
                         req, sizeof(req), MODBUS_FUNC_WRITE_SINGLE_COIL, MODBUS_EXCEPTION_ILLEGAL_DATA_VALUE);
    }
    {
        /* qty=2 -> byte_count는 1이어야 하는데 2로 보냄 */
        uint8_t req[] = {0x0F, 0x00, 0x00, 0x00, 0x02, 0x02, 0x00, 0x00};
        check_exception("boundary: Write Multiple Coils byte_count mismatch -> Illegal Data Value",
                         req, sizeof(req), MODBUS_FUNC_WRITE_MULTIPLE_COILS, MODBUS_EXCEPTION_ILLEGAL_DATA_VALUE);
    }
    {
        /* qty=2 -> byte_count는 4여야 하는데 3으로 보냄 */
        uint8_t req[] = {0x10, 0x00, 0x00, 0x00, 0x02, 0x03, 0x00, 0x00, 0x00};
        check_exception("boundary: Write Multiple Registers byte_count mismatch -> Illegal Data Value",
                         req, sizeof(req), MODBUS_FUNC_WRITE_MULTIPLE_REGISTERS, MODBUS_EXCEPTION_ILLEGAL_DATA_VALUE);
    }
    {
        uint8_t req[] = {0x0F, 0x00, 0x7F, 0x00, 0x02, 0x01, 0x02}; /* addr=127, qty=2 -> 129 > 128 */
        check_exception("boundary: Write Multiple Coils addr+qty overflow -> Illegal Data Address",
                         req, sizeof(req), MODBUS_FUNC_WRITE_MULTIPLE_COILS, MODBUS_EXCEPTION_ILLEGAL_DATA_ADDRESS);
    }

    /* ---- 17~20: 나머지 4개 Function Codes의 성공 경로 -- 코일은 addr 50, 레지스터는 addr 125
       사용 (파일 맨 위 주석 참고: 읽기 케이스가 쓰는 주소와 겹치지 않아야 반복 호출에도
       안전).
       쓰기 응답은 성공해도 그저 요청을 반사하거나 addr/qty를 되돌려줄 뿐이라, 응답 바이트만
       보면 modbus_build_response()가 실제로 coils[]/holding_registers[] 내부 테이블에 값을
       쓰지 않고도 같은 응답을 만들어낼 수 있다 -- 그래서 각 쓰기 직후 같은 주소를 Read로 되짚어
       실제로 저장됐는지 확인한다(쓰기 직후 바로 읽어야 다음 쓰기가 같은 주소를 덮어쓰기 전에
       검증됨). */
    {
        uint8_t req[] = {0x05, 0x00, 0x32, 0xFF, 0x00}; /* addr=50, ON */
        check_exact("0x05 Write Single Coil success", req, sizeof(req), req, sizeof(req)); /* 성공 응답=요청 반사 */
    }
    {
        uint8_t req[] = {0x01, 0x00, 0x32, 0x00, 0x01}; /* Read Coils addr=50, qty=1 */
        uint8_t exp[] = {0x01, 0x01, 0x01}; /* coil50 실제로 1(ON)이어야 함 */
        check_exact("0x05 Write Single Coil actually persisted (read-back)", req, sizeof(req), exp, sizeof(exp));
    }
    {
        uint8_t req[] = {0x06, 0x00, 0x7D, 0x12, 0x34}; /* addr=125, value=0x1234 */
        check_exact("0x06 Write Single Register success", req, sizeof(req), req, sizeof(req));
    }
    {
        uint8_t req[] = {0x03, 0x00, 0x7D, 0x00, 0x01}; /* Read Holding Registers addr=125, qty=1 */
        uint8_t exp[] = {0x03, 0x02, 0x12, 0x34}; /* reg125 실제로 0x1234여야 함 */
        check_exact("0x06 Write Single Register actually persisted (read-back)", req, sizeof(req), exp, sizeof(exp));
    }
    {
        uint8_t req[] = {0x0F, 0x00, 0x32, 0x00, 0x02, 0x01, 0x02}; /* addr=50, qty=2, byte=0x02 -> coil50=0,coil51=1 */
        uint8_t exp[] = {0x0F, 0x00, 0x32, 0x00, 0x02};
        check_exact("0x0F Write Multiple Coils success", req, sizeof(req), exp, sizeof(exp));
    }
    {
        uint8_t req[] = {0x01, 0x00, 0x32, 0x00, 0x02}; /* Read Coils addr=50, qty=2 */
        uint8_t exp[] = {0x01, 0x01, 0x02}; /* coil50=0,coil51=1 실제로 반영됐어야 함 */
        check_exact("0x0F Write Multiple Coils actually persisted (read-back)", req, sizeof(req), exp, sizeof(exp));
    }
    {
        uint8_t req[] = {0x10, 0x00, 0x7D, 0x00, 0x02, 0x04, 0x00, 0x0A, 0x00, 0x0B}; /* addr=125, qty=2 */
        uint8_t exp[] = {0x10, 0x00, 0x7D, 0x00, 0x02};
        check_exact("0x10 Write Multiple Registers success", req, sizeof(req), exp, sizeof(exp));
    }
    {
        uint8_t req[] = {0x03, 0x00, 0x7D, 0x00, 0x02}; /* Read Holding Registers addr=125, qty=2 */
        uint8_t exp[] = {0x03, 0x04, 0x00, 0x0A, 0x00, 0x0B}; /* reg125=0x000A, reg126=0x000B 실제로 반영됐어야 함 */
        check_exact("0x10 Write Multiple Registers actually persisted (read-back)", req, sizeof(req), exp, sizeof(exp));
    }

    printf("%d passed, %d failed (%d total)\n", g_pass, g_fail, g_pass + g_fail);
    return g_fail == 0;
}
