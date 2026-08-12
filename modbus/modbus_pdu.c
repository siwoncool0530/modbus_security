#include "modbus_pdu.h"
#include <string.h>

/* 데모용 코일/레지스터 데이터 모델. 코일은 내부적으로 바이트 하나에 0/1로 저장하고,
   와이어 포맷(8개씩 비트 패킹)으로는 인코딩/디코딩 경계에서만 변환한다. */
static uint16_t holding_registers[MODBUS_TABLE_SIZE];
static uint16_t input_registers[MODBUS_TABLE_SIZE];
static uint8_t coils[MODBUS_TABLE_SIZE];
static uint8_t discrete_inputs[MODBUS_TABLE_SIZE];
static int table_initialized = 0;

static void ensure_table_initialized(void)
{
    int i;

    if (table_initialized) {
        return;
    }
    for (i = 0; i < MODBUS_TABLE_SIZE; i++) {
        holding_registers[i] = (uint16_t) (0x1000 + i);
        input_registers[i] = (uint16_t) (0x2000 + i);
        coils[i] = (uint8_t) (i % 2);
        discrete_inputs[i] = (uint8_t) ((i + 1) % 2);
    }
    table_initialized = 1;
}

static void put_u16(uint8_t *out, uint16_t v)
{
    out[0] = (uint8_t) (v >> 8);
    out[1] = (uint8_t) (v & 0xFF);
}

static uint16_t get_u16(const uint8_t *in)
{
    return (uint16_t) (((uint16_t) in[0] << 8) | in[1]);
}

static size_t bits_to_bytes(uint16_t nb)
{
    return (size_t) ((nb + 7) / 8);
}

static void build_exception(uint8_t func, uint8_t exc_code, uint8_t *resp_pdu, size_t *resp_len)
{
    resp_pdu[0] = (uint8_t) (func | MODBUS_EXCEPTION_BIT);
    resp_pdu[1] = exc_code;
    *resp_len = 2;
}

int modbus_build_request(uint8_t func, uint16_t addr, uint16_t value_or_qty,
                          uint8_t *out_pdu, size_t *out_pdu_len)
{
    switch (func) {
    case MODBUS_FUNC_READ_COILS:
    case MODBUS_FUNC_READ_DISCRETE_INPUTS:
    case MODBUS_FUNC_READ_HOLDING_REGISTERS:
    case MODBUS_FUNC_READ_INPUT_REGISTERS: {
        uint16_t max = (func == MODBUS_FUNC_READ_COILS || func == MODBUS_FUNC_READ_DISCRETE_INPUTS)
                           ? MODBUS_MAX_READ_BITS
                           : MODBUS_MAX_READ_REGISTERS;
        if (value_or_qty < 1 || value_or_qty > max) {
            return 0;
        }
        out_pdu[0] = func;
        put_u16(out_pdu + 1, addr);
        put_u16(out_pdu + 3, value_or_qty);
        *out_pdu_len = 5;
        return 1;
    }
    case MODBUS_FUNC_WRITE_SINGLE_COIL:
        out_pdu[0] = func;
        put_u16(out_pdu + 1, addr);
        put_u16(out_pdu + 3, value_or_qty != 0 ? 0xFF00u : 0x0000u);
        *out_pdu_len = 5;
        return 1;
    case MODBUS_FUNC_WRITE_SINGLE_REGISTER:
        out_pdu[0] = func;
        put_u16(out_pdu + 1, addr);
        put_u16(out_pdu + 3, value_or_qty);
        *out_pdu_len = 5;
        return 1;
    case MODBUS_FUNC_WRITE_MULTIPLE_COILS: {
        uint16_t qty = value_or_qty;
        size_t byte_count;
        uint16_t i;

        if (qty < 1 || qty > MODBUS_MAX_WRITE_BITS) {
            return 0;
        }
        byte_count = bits_to_bytes(qty);
        out_pdu[0] = func;
        put_u16(out_pdu + 1, addr);
        put_u16(out_pdu + 3, qty);
        out_pdu[5] = (uint8_t) byte_count;
        memset(out_pdu + 6, 0, byte_count);
        for (i = 0; i < qty; i++) {
            /* 데모용 자동 생성 값: 코일 인덱스 기반 0/1 교대 패턴 */
            if (i % 2) {
                out_pdu[6 + i / 8] |= (uint8_t) (1u << (i % 8));
            }
        }
        *out_pdu_len = 6 + byte_count;
        return 1;
    }
    case MODBUS_FUNC_WRITE_MULTIPLE_REGISTERS: {
        uint16_t qty = value_or_qty;
        uint16_t i;

        if (qty < 1 || qty > MODBUS_MAX_WRITE_REGISTERS) {
            return 0;
        }
        out_pdu[0] = func;
        put_u16(out_pdu + 1, addr);
        put_u16(out_pdu + 3, qty);
        out_pdu[5] = (uint8_t) (qty * 2);
        for (i = 0; i < qty; i++) {
            /* 데모용 자동 생성 값: 시작주소+인덱스 (secure_send_demo.c의 기존 패턴과 동일한 취지) */
            put_u16(out_pdu + 6 + (size_t) i * 2, (uint16_t) (addr + i));
        }
        *out_pdu_len = 6 + (size_t) qty * 2;
        return 1;
    }
    default:
        return 0;
    }
}

int modbus_build_response(const uint8_t *req_pdu, size_t req_len, uint8_t *resp_pdu, size_t *resp_len)
{
    uint8_t func;
    uint16_t addr, qty;

    if (req_len < 1) {
        return 0;
    }
    func = req_pdu[0];
    ensure_table_initialized();

    switch (func) {
    case MODBUS_FUNC_READ_COILS:
    case MODBUS_FUNC_READ_DISCRETE_INPUTS: {
        const uint8_t *table = (func == MODBUS_FUNC_READ_COILS) ? coils : discrete_inputs;
        size_t byte_count;
        uint16_t i;

        if (req_len < 5) {
            build_exception(func, MODBUS_EXCEPTION_ILLEGAL_DATA_VALUE, resp_pdu, resp_len);
            return 1;
        }
        addr = get_u16(req_pdu + 1);
        qty = get_u16(req_pdu + 3);
        if (qty < 1 || qty > MODBUS_MAX_READ_BITS) {
            build_exception(func, MODBUS_EXCEPTION_ILLEGAL_DATA_VALUE, resp_pdu, resp_len);
            return 1;
        }
        if ((uint32_t) addr + qty > MODBUS_TABLE_SIZE) {
            build_exception(func, MODBUS_EXCEPTION_ILLEGAL_DATA_ADDRESS, resp_pdu, resp_len);
            return 1;
        }
        byte_count = bits_to_bytes(qty);
        resp_pdu[0] = func;
        resp_pdu[1] = (uint8_t) byte_count;
        memset(resp_pdu + 2, 0, byte_count);
        for (i = 0; i < qty; i++) {
            if (table[addr + i]) {
                resp_pdu[2 + i / 8] |= (uint8_t) (1u << (i % 8));
            }
        }
        *resp_len = 2 + byte_count;
        return 1;
    }
    case MODBUS_FUNC_READ_HOLDING_REGISTERS:
    case MODBUS_FUNC_READ_INPUT_REGISTERS: {
        const uint16_t *table =
            (func == MODBUS_FUNC_READ_HOLDING_REGISTERS) ? holding_registers : input_registers;
        uint16_t i;

        if (req_len < 5) {
            build_exception(func, MODBUS_EXCEPTION_ILLEGAL_DATA_VALUE, resp_pdu, resp_len);
            return 1;
        }
        addr = get_u16(req_pdu + 1);
        qty = get_u16(req_pdu + 3);
        if (qty < 1 || qty > MODBUS_MAX_READ_REGISTERS) {
            build_exception(func, MODBUS_EXCEPTION_ILLEGAL_DATA_VALUE, resp_pdu, resp_len);
            return 1;
        }
        if ((uint32_t) addr + qty > MODBUS_TABLE_SIZE) {
            build_exception(func, MODBUS_EXCEPTION_ILLEGAL_DATA_ADDRESS, resp_pdu, resp_len);
            return 1;
        }
        resp_pdu[0] = func;
        resp_pdu[1] = (uint8_t) (qty * 2);
        for (i = 0; i < qty; i++) {
            put_u16(resp_pdu + 2 + (size_t) i * 2, table[addr + i]);
        }
        *resp_len = 2 + (size_t) qty * 2;
        return 1;
    }
    case MODBUS_FUNC_WRITE_SINGLE_COIL: {
        uint16_t value;

        if (req_len < 5) {
            build_exception(func, MODBUS_EXCEPTION_ILLEGAL_DATA_VALUE, resp_pdu, resp_len);
            return 1;
        }
        addr = get_u16(req_pdu + 1);
        value = get_u16(req_pdu + 3);
        if (value != 0x0000u && value != 0xFF00u) {
            build_exception(func, MODBUS_EXCEPTION_ILLEGAL_DATA_VALUE, resp_pdu, resp_len);
            return 1;
        }
        if (addr >= MODBUS_TABLE_SIZE) {
            build_exception(func, MODBUS_EXCEPTION_ILLEGAL_DATA_ADDRESS, resp_pdu, resp_len);
            return 1;
        }
        coils[addr] = (value == 0xFF00u) ? 1 : 0;
        memcpy(resp_pdu, req_pdu, 5); /* 성공 응답은 요청을 그대로 반사 */
        *resp_len = 5;
        return 1;
    }
    case MODBUS_FUNC_WRITE_SINGLE_REGISTER: {
        if (req_len < 5) {
            build_exception(func, MODBUS_EXCEPTION_ILLEGAL_DATA_VALUE, resp_pdu, resp_len);
            return 1;
        }
        addr = get_u16(req_pdu + 1);
        if (addr >= MODBUS_TABLE_SIZE) {
            build_exception(func, MODBUS_EXCEPTION_ILLEGAL_DATA_ADDRESS, resp_pdu, resp_len);
            return 1;
        }
        holding_registers[addr] = get_u16(req_pdu + 3);
        memcpy(resp_pdu, req_pdu, 5); /* 성공 응답은 요청을 그대로 반사 */
        *resp_len = 5;
        return 1;
    }
    case MODBUS_FUNC_WRITE_MULTIPLE_COILS: {
        size_t byte_count;
        uint16_t i;

        if (req_len < 6) {
            build_exception(func, MODBUS_EXCEPTION_ILLEGAL_DATA_VALUE, resp_pdu, resp_len);
            return 1;
        }
        addr = get_u16(req_pdu + 1);
        qty = get_u16(req_pdu + 3);
        byte_count = req_pdu[5];
        if (qty < 1 || qty > MODBUS_MAX_WRITE_BITS || byte_count != bits_to_bytes(qty) ||
            req_len < 6 + byte_count) {
            build_exception(func, MODBUS_EXCEPTION_ILLEGAL_DATA_VALUE, resp_pdu, resp_len);
            return 1;
        }
        if ((uint32_t) addr + qty > MODBUS_TABLE_SIZE) {
            build_exception(func, MODBUS_EXCEPTION_ILLEGAL_DATA_ADDRESS, resp_pdu, resp_len);
            return 1;
        }
        for (i = 0; i < qty; i++) {
            coils[addr + i] = (uint8_t) ((req_pdu[6 + i / 8] >> (i % 8)) & 1);
        }
        resp_pdu[0] = func;
        put_u16(resp_pdu + 1, addr);
        put_u16(resp_pdu + 3, qty);
        *resp_len = 5;
        return 1;
    }
    case MODBUS_FUNC_WRITE_MULTIPLE_REGISTERS: {
        size_t byte_count;
        uint16_t i;

        if (req_len < 6) {
            build_exception(func, MODBUS_EXCEPTION_ILLEGAL_DATA_VALUE, resp_pdu, resp_len);
            return 1;
        }
        addr = get_u16(req_pdu + 1);
        qty = get_u16(req_pdu + 3);
        byte_count = req_pdu[5];
        if (qty < 1 || qty > MODBUS_MAX_WRITE_REGISTERS || byte_count != (size_t) qty * 2 ||
            req_len < 6 + byte_count) {
            build_exception(func, MODBUS_EXCEPTION_ILLEGAL_DATA_VALUE, resp_pdu, resp_len);
            return 1;
        }
        if ((uint32_t) addr + qty > MODBUS_TABLE_SIZE) {
            build_exception(func, MODBUS_EXCEPTION_ILLEGAL_DATA_ADDRESS, resp_pdu, resp_len);
            return 1;
        }
        for (i = 0; i < qty; i++) {
            holding_registers[addr + i] = get_u16(req_pdu + 6 + (size_t) i * 2);
        }
        resp_pdu[0] = func;
        put_u16(resp_pdu + 1, addr);
        put_u16(resp_pdu + 3, qty);
        *resp_len = 5;
        return 1;
    }
    default:
        build_exception(func, MODBUS_EXCEPTION_ILLEGAL_FUNCTION, resp_pdu, resp_len);
        return 1;
    }
}
