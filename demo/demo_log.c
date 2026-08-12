#include "demo_log.h"
#include <stdio.h>
#include <stdarg.h>

static FILE *g_log = NULL;

void log_open(const char *path)
{
    g_log = fopen(path, "w");
    if (g_log == NULL) {
        fprintf(stderr, "Warning: could not open log file %s -- continuing without one\n", path);
    }
}

void log_close_atexit(void)
{
    if (g_log != NULL) {
        fclose(g_log);
        g_log = NULL;
    }
}

void log_detail(const char *fmt, ...)
{
    va_list ap;

    if (g_log != NULL) {
        va_start(ap, fmt);
        vfprintf(g_log, fmt, ap);
        va_end(ap);
        fflush(g_log); /* 중도 중단될 경우 대비 */
    }
}

void log_summary(const char *fmt, ...)
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

void print_hex(const char *label, const uint8_t *buf, size_t len)
{
    size_t i;
    log_detail("%s (%u bytes): ", label, (unsigned int) len);
    for (i = 0; i < len; i++) {
        log_detail("%02X ", buf[i]);
    }
    log_detail("\n");
}