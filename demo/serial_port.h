/* 송신·수신 데모가 공유하는, COM/tty 포트를 열고 설정하고 읽고 쓰기 위한 코드.
   Windows(COM3, ...)나 Linux(/dev/ttyUSB0, ...)에서 실제 하드웨어와 바이트를 주고받는 데 필요 */
#ifndef SECURITY_DEMO_SERIAL_PORT_H
#define SECURITY_DEMO_SERIAL_PORT_H

#include <stddef.h>

#ifdef _WIN32
#include <windows.h>
#endif

typedef struct {
#ifdef _WIN32
    HANDLE h;
#else
    int fd;
#endif
    int read_interval_timeout_us;
} serial_port_t;

/* port_name(Windows "COM3", Linux "/dev/ttyUSB0" 등)을 읽기/쓰기용으로 열고 baud, 8N1, 흐름 제어 없음으로 설정.
   read_interval_timeout_us는 serial_port_read()가 "프레임 종료"로 간주하는 바이트 간 유휴 간격을
   마이크로초 단위로 지정 (순수 송신자는 의미 없으므로 0을 넘기면 됨). Modbus 실제 T3.5는 baud가 높을수록
   1ms보다 훨씬 짧아지므로 (예: 115200 baud -> 약 334us) 밀리초로는 표현 불가 -- 그래서 마이크로초 단위.
   POSIX 쪽은 select()의 tv_usec으로 그대로 전달되어 정밀하게 지켜지지만, Windows COMMTIMEOUTS는
   ReadIntervalTimeout이 밀리초(DWORD) 단위라 서브밀리초 값은 올림하여 최소 1ms로 클램프됨 -- 즉 Windows
   경로는 근사치이며, 실제 목표 환경인 CM5(Linux)에서만 스펙대로 정밀하게 동작함.
   성공 시 0, 실패 시 -1을 반환 (실패 메시지는 stderr에 출력). */
int serial_port_open(serial_port_t *sp,
                      const char *port_name,
                      long baud,
                      int read_interval_timeout_us);

void serial_port_close(serial_port_t *sp);

/* len 길이만큼 정확히 write (blocking)
성공 시 0, 실패시 -1을 반환 */
int serial_port_write(serial_port_t *sp, const void *buf, size_t len);

/* 첫 바이트가 도착할 때까지 최대 30초를 기다린 뒤, max_len 바이트를 모두 모으거나
   새 바이트 없이 read_interval_timeout_us가 경과할 때까지(이 간격을 프레임 경계로 간주) 계속 누적.
   성공 시 읽은 바이트 수를 반환(아무 것도 도착하지 않았으면 0), I/O 오류 시 -1을 반환. */
long serial_port_read(serial_port_t *sp, void *buf, size_t max_len);

/* 아직 읽지 않은 채 커널/드라이버 RX 버퍼에 남아있는 바이트를 모두 버림.
   프레임이 거부됐을 때(형식 오류/HMAC/CRC) 호출하는 용도 -- 잘려나간 프레임의
   나머지 꼬리 바이트가 버퍼에 남아있으면 다음 serial_port_read() 호출이 그걸
   다음 프레임의 시작으로 잘못 읽어버리므로, 거부 즉시 비워서 다음 읽기가
   깨끗한 상태에서 시작하도록 함. 성공한 프레임 뒤에는 호출하면 안 됨 -- 송신
   측이 프레임을 연달아 보냈다면 다음 정상 프레임이 이미 버퍼에 와 있을 수
   있고, 그걸 버리면 안 되기 때문. */
void serial_port_drain(serial_port_t *sp);

/* ms 밀리초 동안 대기. 다중 프레임 전송 시 프레임 사이에 사용되어, 연속된 프레임이 수신 측의 유휴 간격 프레이밍(
   serial_port_open()의 read_interval_timeout_us)이 구분할 수 있는 속도보다 빠르게 회선 위에서 이어지지 않도록 함. */
void serial_sleep_ms(int ms);

#endif /* SECURITY_DEMO_SERIAL_PORT_H */