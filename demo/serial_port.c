#include "serial_port.h"
#include <stdio.h>
#include <string.h>

long modbus_t35_us(long baud)
{
    long t35 = (baud > 19200) ? 1750 : (long) (3.5 * 11.0 * 1000000.0 / (double) baud);
    return (t35 > MODBUS_T35_MIN_GAP_US) ? t35 : MODBUS_T35_MIN_GAP_US;
}

#ifdef _WIN32

int serial_port_open(serial_port_t *sp, const char *port_name, long baud, int read_interval_timeout_us)
{
    char full_name[32];
    DCB dcb;
    COMMTIMEOUTS timeouts;
    DWORD read_interval_timeout_ms;

    /* "\\.\COMn" form is required for COM10 and above, harmless for COM1-9. */
    _snprintf(full_name, sizeof(full_name), "\\\\.\\%s", port_name);

    sp->h = CreateFileA(full_name, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (sp->h == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "Could not open %s (error %lu)\n", port_name, GetLastError());
        return -1;
    }

    memset(&dcb, 0, sizeof(dcb));
    dcb.DCBlength = sizeof(dcb);
    if (!GetCommState(sp->h, &dcb)) {
        fprintf(stderr, "GetCommState(%s) failed (error %lu)\n", port_name, GetLastError());
        CloseHandle(sp->h);
        return -1;
    }
    dcb.BaudRate = (DWORD) baud;
    dcb.ByteSize = 8;
    dcb.Parity = NOPARITY;
    dcb.StopBits = ONESTOPBIT;
    dcb.fBinary = TRUE;
    dcb.fParity = FALSE;
    if (!SetCommState(sp->h, &dcb)) {
        fprintf(stderr, "SetCommState(%s) failed (error %lu)\n", port_name, GetLastError());
        CloseHandle(sp->h);
        return -1;
    }

    /* COMMTIMEOUTS::ReadIntervalTimeout은 밀리초 (DWORD)
    -- Modbus T3.5 규격을 높은 baud에서 구현 불가 (e.g. ~334us at 115200), ms로 올림 처리
    0은 0으로 유지 (sender's "don't care" case, see serial_port.h). */
    read_interval_timeout_ms = (read_interval_timeout_us == 0)
                                    ? 0
                                    : (DWORD) ((read_interval_timeout_us + 999) / 1000);

    memset(&timeouts, 0, sizeof(timeouts));
    timeouts.ReadIntervalTimeout = read_interval_timeout_ms;
    timeouts.ReadTotalTimeoutConstant = 30000; // 첫 바이트까지 최대 30초 대기
    timeouts.ReadTotalTimeoutMultiplier = 0;
    timeouts.WriteTotalTimeoutConstant = 2000;
    timeouts.WriteTotalTimeoutMultiplier = 0;
    if (!SetCommTimeouts(sp->h, &timeouts)) {
        fprintf(stderr, "SetCommTimeouts(%s) failed (error %lu)\n", port_name, GetLastError());
        CloseHandle(sp->h);
        return -1;
    }

    PurgeComm(sp->h, PURGE_RXCLEAR | PURGE_TXCLEAR);
    sp->read_interval_timeout_us = read_interval_timeout_us;
    return 0;
}

void serial_port_close(serial_port_t *sp)
{
    CloseHandle(sp->h);
}

int serial_port_write(serial_port_t *sp, const void *buf, size_t len)
{
    DWORD written;

    if (!WriteFile(sp->h, buf, (DWORD) len, &written, NULL) || written != len) {
        fprintf(stderr, "WriteFile failed (error %lu)\n", GetLastError());
        return -1;
    }
    return 0;
}

long serial_port_read(serial_port_t *sp, void *buf, size_t max_len)
{
    DWORD n = 0;

    /* open() 시점의 SetCommTimeouts()가 이미 "첫 바이트까지 최대 30초 대기"와
    "유휴 간격이 프레임 종료를 의미" 동작, ReadFile() 호출 한 번으로 전체 작업 처리. */
    if (!ReadFile(sp->h, buf, (DWORD) max_len, &n, NULL)) {
        fprintf(stderr, "ReadFile failed (error %lu)\n", GetLastError());
        return -1;
    }
    return (long) n;
}

void serial_port_drain(serial_port_t *sp)
{
    PurgeComm(sp->h, PURGE_RXCLEAR);
}

void serial_sleep_ms(int ms)
{
    Sleep((DWORD) ms);
}

#else /* POSIX */

#define _POSIX_C_SOURCE 199309L /* nanosleep() */

#include <fcntl.h>
#include <termios.h>
#include <unistd.h>
#include <errno.h>
#include <sys/select.h>
#include <sys/ioctl.h>
#include <linux/serial.h>
#include <stdint.h>
#include <time.h>
#include <stdlib.h>

static speed_t baud_to_speed(long baud)
{
    switch (baud) {
    case 1200:
        return B1200;
    case 2400:
        return B2400;
    case 4800:
        return B4800;
    case 9600:
        return B9600;
    case 19200:
        return B19200;
    case 38400:
        return B38400;
    case 57600:
        return B57600;
    case 115200:
        return B115200;
    case 230400:
        return B230400;
    default:
        return (speed_t) -1;
    }
}

int serial_port_open(serial_port_t *sp, const char *port_name, long baud, int read_interval_timeout_us)
{
    struct termios tty;
    speed_t speed;

    sp->fd = open(port_name, O_RDWR | O_NOCTTY);
    if (sp->fd < 0) {
        fprintf(stderr, "Could not open %s (%s)\n", port_name, strerror(errno));
        return -1;
    }

    speed = baud_to_speed(baud);
    if (speed == (speed_t) -1) {
        fprintf(stderr, "Unsupported baud rate %ld\n", baud);
        close(sp->fd);
        return -1;
    }

    memset(&tty, 0, sizeof(tty));
    if (tcgetattr(sp->fd, &tty) != 0) {
        fprintf(stderr, "tcgetattr(%s) failed (%s)\n", port_name, strerror(errno));
        close(sp->fd);
        return -1;
    }

    cfmakeraw(&tty); /* raw byte I/O, no line discipline / echo / signals */
    cfsetispeed(&tty, speed);
    cfsetospeed(&tty, speed);

    tty.c_cflag &= ~PARENB; /* 8N1 */
    tty.c_cflag &= ~CSTOPB;
    tty.c_cflag &= ~CSIZE;
    tty.c_cflag |= CS8;
    tty.c_cflag &= ~CRTSCTS; /* no hardware flow control */
    tty.c_cflag |= CREAD | CLOCAL;

    /* 실제 프레임 경계 타이밍은 serial_port_read() 안에서 select()를 통해 처리
       여기서는 그저 버퍼에 아무것도 없을 때 읽기가 블로킹되지 않도록만 만들고,
       실제 타이밍 제어는 serial_port_read()의 select() 루프가 담당. */
    tty.c_cc[VMIN] = 0;
    tty.c_cc[VTIME] = 0;

    if (tcsetattr(sp->fd, TCSANOW, &tty) != 0) {
        fprintf(stderr, "tcsetattr(%s) failed (%s)\n", port_name, strerror(errno));
        close(sp->fd);
        return -1;
    }

    tcflush(sp->fd, TCIOFLUSH);
    sp->read_interval_timeout_us = read_interval_timeout_us;

    /* low_latency 미설정 시 일부 드라이버는 수신 바이트를 워크큐로 미뤄 깨우기 때문에
       (효율성 트레이드오프, 보통 1 jiffy 정도 지연) select()가 하드웨어 FIFO에 이미 도착한
       바이트를 즉시 못 볼 수 있음 -- 9600 baud에서 T3.5(~4ms)보다 이 지연이 커서 프레임이
       조기에 잘리는 것으로 의심됨. TIOCGSERIAL/TIOCSSERIAL 둘 다 실패해도(드라이버가
       이 플래그를 안 쓰는 경우) 치명적이지 않으므로 무시하고 계속 진행. */
    {
        struct serial_struct ss;
        memset(&ss, 0, sizeof(ss));
        if (ioctl(sp->fd, TIOCGSERIAL, &ss) == 0) {
            ss.flags |= ASYNC_LOW_LATENCY;
            if (ioctl(sp->fd, TIOCSSERIAL, &ss) == 0) {
                fprintf(stderr, "low_latency enabled on %s\n", port_name);
            }
        }
    }

    /* UART의 커널 드라이버가 RS485 제어를 지원한다면(rs485_probe.c) 드라이버가 하드웨어 차원에서
       버스 방향 전환을 처리하도록 함. TIOCGRS485가 실패하면 이 포트는 이를 지원하지 않는다는 뜻.
       트랜시버가 스스로 방향을 자동 감지하거나, 아니면 이 개념 자체가 적용되지 않는 단순한 점대점 연결(예:
       원래 대상으로 만들어진 FTDI/CP210x USB-시리얼 루프백). 어느 쪽이든 read()/write()로 계속 진행. */
    {
        struct serial_rs485 rs485conf;
        memset(&rs485conf, 0, sizeof(rs485conf));
        if (ioctl(sp->fd, TIOCGRS485, &rs485conf) == 0) {
            rs485conf.flags |= SER_RS485_ENABLED;
            if (ioctl(sp->fd, TIOCSRS485, &rs485conf) == 0) {
                fprintf(stderr, "RS485 direction control enabled on %s\n", port_name);
            }
        }
    }

    return 0;
}

void serial_port_close(serial_port_t *sp)
{
    close(sp->fd);
}

int serial_port_write(serial_port_t *sp, const void *buf, size_t len)
{
    const uint8_t *p = (const uint8_t *) buf;
    size_t written = 0;
    ssize_t n;

    while (written < len) {
        n = write(sp->fd, p + written, len - written);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            fprintf(stderr, "write failed (%s)\n", strerror(errno));
            return -1;
        }
        written += (size_t) n;
    }
    return 0;
}

long serial_port_read(serial_port_t *sp, void *buf, size_t max_len)
{
    uint8_t *p = (uint8_t *) buf;
    size_t total = 0;
    int have_first_byte = 0;

    for (;;) {
        fd_set fds;
        struct timeval tv;
        int rc;
        ssize_t n;

        FD_ZERO(&fds);
        FD_SET(sp->fd, &fds);

        if (!have_first_byte) {
            tv.tv_sec = 30; /* 첫 바이트까지 30초 기다림 */
            tv.tv_usec = 0;
        } else {
            tv.tv_sec = sp->read_interval_timeout_us / 1000000;
            tv.tv_usec = sp->read_interval_timeout_us % 1000000;
        }

        rc = select(sp->fd + 1, &fds, NULL, NULL, &tv);
        if (rc < 0) {
            if (errno == EINTR) {
                continue;
            }
            fprintf(stderr, "select failed (%s)\n", strerror(errno));
            return -1;
        }
        if (rc == 0) {
            break; /* 타임아웃 (프레임이 끝나거나 아무 것도 안오거나) */
        }

        n = read(sp->fd, p + total, max_len - total);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            fprintf(stderr, "read failed (%s)\n", strerror(errno));
            return -1;
        }
        if (n == 0) {
            break;
        }

        total += (size_t) n;
        have_first_byte = 1;
        if (total >= max_len) {
            break;
        }
    }

    return (long) total;
}

void serial_port_drain(serial_port_t *sp)
{
    tcflush(sp->fd, TCIFLUSH);
}

void serial_sleep_ms(int ms)
{
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (long) (ms % 1000) * 1000000L;
    nanosleep(&ts, NULL);
}

#endif