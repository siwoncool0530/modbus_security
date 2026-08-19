#ifndef SECURITY_DEMO_MAIN_H
#define SECURITY_DEMO_MAIN_H

/* main.c에서만 쓰는 modbus 함수 코드/예외 코드 표시·검증 헬퍼.
   main.c에서만 include하므로 static으로 둬도 ODR 문제 없음. */

#include "../modbus/modbus_pdu.h"

static const char *modbus_exception_name(uint8_t code)
{
    switch (code) {
    case MODBUS_EXCEPTION_ILLEGAL_FUNCTION:
        return "Illegal Function";
    case MODBUS_EXCEPTION_ILLEGAL_DATA_ADDRESS:
        return "Illegal Data Address";
    case MODBUS_EXCEPTION_ILLEGAL_DATA_VALUE:
        return "Illegal Data Value";
    default:
        return "unknown";
    }
}

static const char *modbus_func_name(uint8_t func)
{
    switch (func) {
    case MODBUS_FUNC_READ_COILS:
        return "Read Coils";
    case MODBUS_FUNC_READ_DISCRETE_INPUTS:
        return "Read Discrete Inputs";
    case MODBUS_FUNC_READ_HOLDING_REGISTERS:
        return "Read Holding Registers";
    case MODBUS_FUNC_READ_INPUT_REGISTERS:
        return "Read Input Registers";
    case MODBUS_FUNC_WRITE_SINGLE_COIL:
        return "Write Single Coil";
    case MODBUS_FUNC_WRITE_SINGLE_REGISTER:
        return "Write Single Register";
    case MODBUS_FUNC_WRITE_MULTIPLE_COILS:
        return "Write Multiple Coils";
    case MODBUS_FUNC_WRITE_MULTIPLE_REGISTERS:
        return "Write Multiple Registers";
    default:
        return "?";
    }
}

static int modbus_func_is_supported(uint8_t func)
{
    switch (func) {
    case MODBUS_FUNC_READ_COILS:
    case MODBUS_FUNC_READ_DISCRETE_INPUTS:
    case MODBUS_FUNC_READ_HOLDING_REGISTERS:
    case MODBUS_FUNC_READ_INPUT_REGISTERS:
    case MODBUS_FUNC_WRITE_SINGLE_COIL:
    case MODBUS_FUNC_WRITE_SINGLE_REGISTER:
    case MODBUS_FUNC_WRITE_MULTIPLE_COILS:
    case MODBUS_FUNC_WRITE_MULTIPLE_REGISTERS:
        return 1;
    default:
        return 0;
    }
}

/* value_or_qty 프롬프트에 붙는 설명은 함수 코드에 따라 의미가 다름 (modbus_pdu.h의
   modbus_build_request() 문서 주석과 동일한 대응). */
static const char *value_or_qty_label(uint8_t func)
{
    switch (func) {
    case MODBUS_FUNC_WRITE_SINGLE_COIL:
        return "Coil value (0=OFF, 1=ON)";
    case MODBUS_FUNC_WRITE_SINGLE_REGISTER:
        return "Register value (0-65535)";
    case MODBUS_FUNC_WRITE_MULTIPLE_COILS:
        return "Quantity of coils to write (values auto-generated)";
    case MODBUS_FUNC_WRITE_MULTIPLE_REGISTERS:
        return "Quantity of registers to write (values auto-generated)";
    default:
        return "Quantity to read";
    }
}

#endif /* SECURITY_DEMO_MAIN_H */
