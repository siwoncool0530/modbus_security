/* UART 환경인지 확인

   빌드:  gcc rs485_probe.c -o rs485_probe
   사용법:  ./rs485_probe /dev/ttyAMA0
*/
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/serial.h>

int main(int argc, char **argv)
{
    int fd;
    struct serial_rs485 rs485conf;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s /dev/ttyAMA0\n", argv[0]);
        return 1;
    }

    fd = open(argv[1], O_RDWR | O_NOCTTY);
    if (fd < 0) {
        perror("open");
        return 1;
    }

    memset(&rs485conf, 0, sizeof(rs485conf));
    if (ioctl(fd, TIOCGRS485, &rs485conf) < 0) {
        printf("TIOCGRS485 failed: %s (errno=%d)\n", strerror(errno), errno);
        printf("-> This UART is NOT configured for kernel RS485 direction control.\n"
               "   Either the transceiver auto-senses direction in hardware (fine,\n"
               "   no software changes needed), or it needs software RTS toggling\n"
               "   instead (see modbus-rtu.c's _modbus_rtu_ioctl_rts()/_modbus_rtu_send()\n"
               "   for the pattern) -- this ioctl alone can't tell those two apart.\n");
        close(fd);
        return 1;
    }

    printf("TIOCGRS485 succeeded -- this UART has kernel RS485 support wired up.\n");
    printf("  SER_RS485_ENABLED       : %s\n", (rs485conf.flags & SER_RS485_ENABLED) ? "yes" : "no");
    printf("  SER_RS485_RTS_ON_SEND   : %s\n",
           (rs485conf.flags & SER_RS485_RTS_ON_SEND) ? "yes" : "no");
    printf("  SER_RS485_RTS_AFTER_SEND: %s\n",
           (rs485conf.flags & SER_RS485_RTS_AFTER_SEND) ? "yes" : "no");
    printf("  delay_rts_before_send   : %u ms\n", rs485conf.delay_rts_before_send);
    printf("  delay_rts_after_send    : %u ms\n", rs485conf.delay_rts_after_send);

    if (rs485conf.flags & SER_RS485_ENABLED) {
        printf("\n-> RS485 mode is ALREADY ENABLED for this port. The kernel is handling\n"
               "   bus direction automatically -- plain read()/write() (what\n"
               "   serial_port.c already does) should work correctly with no changes.\n");
    } else {
        printf("\n-> The driver supports RS485 mode but it's currently OFF for this port.\n"
               "   Either enable it (TIOCSRS485 with SER_RS485_ENABLED set, matching\n"
               "   modbus_rtu_set_serial_mode(MODBUS_RTU_RS485) in modbus-rtu.c), or\n"
               "   confirm the transceiver auto-senses direction in hardware instead.\n");
    }

    close(fd);
    return 0;
}
