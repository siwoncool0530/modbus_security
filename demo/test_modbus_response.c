/* modbus_pdu_self_test()를 실행하는 커맨드라인 러너. 테스트 케이스 자체는
   modbus/modbus_pdu_selftest.c에 있음 (demo/main.c 옵션 3과 공유). */
#include "../modbus/modbus_pdu_selftest.h"
#include <stdlib.h>

int main(void)
{
    return modbus_pdu_self_test() ? EXIT_SUCCESS : EXIT_FAILURE;
}
