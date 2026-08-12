/* secure_send_demo.c와 secure_recv_demo.c가 공유하는 파일 로깅 유틸리티 --
   상세 진단은 로그 파일에만, 프레임당 요약은 로그 파일과 콘솔 양쪽에 기록.
   main.c는 로그 파일이 없는 인터랙티브 도구이므로 이 헤더를 쓰지 않고
   자체 콘솔 전용 print_hex()를 따로 둠 (같은 이름의 extern 선언과 충돌하므로
   두 세계를 섞지 않음). */
#ifndef SECURITY_DEMO_DEMO_LOG_H
#define SECURITY_DEMO_DEMO_LOG_H

#include <stdint.h>
#include <stddef.h>

/* path를 열어 이후 log_detail()/log_summary() 호출의 대상으로 삼음.
   열기 실패 시 경고만 출력하고 로그 파일 없이 계속 진행 (g_log == NULL이면
   log_detail()은 조용히 무시, log_summary()는 콘솔 출력만 유지). */
void log_open(const char *path);

/* atexit()에 등록해 로그 파일을 정리하는 용도. */
void log_close_atexit(void);

/* 전체 상세 정보(PDU/회선 프레임 16진수 덤프, 전송별 진단 정보) - 로그 파일에만 기록.
   크기가 제각각인 여러 프레임을 한 번에 실행하면 터미널에서 실시간으로 읽기엔 양이 너무 많으므로,
   특정 프레임을 나중에 살펴봐야 할 때를 위해 로그 파일에 보관. */
void log_detail(const char *fmt, ...);

/* 프레임당 한 줄로 결과 및 성공/실패 요약 메시지 - 콘솔과 로그 파일 양쪽에 기록. */
void log_summary(const char *fmt, ...);

/* buf의 len바이트를 16진수로 log_detail()에 기록 (로그 파일에만, 콘솔에는 안 나감). */
void print_hex(const char *label, const uint8_t *buf, size_t len);

#endif /* SECURITY_DEMO_DEMO_LOG_H */