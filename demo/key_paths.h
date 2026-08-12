/* 세 데모(main.c, secure_send_demo.c, secure_recv_demo.c)가 공유하는, 실행 파일
   위치를 기준으로 한 경로 계산과 keys.txt 탐색 로직. */
#ifndef SECURITY_DEMO_KEY_PATHS_H
#define SECURITY_DEMO_KEY_PATHS_H

#include <stddef.h>

/* "<argv0을 담고 있는 디렉터리>/filename" 형태의 문자열을 out에 만들어 넣음.
   argv0에 디렉터리 구성요소가 없으면 그냥 filename으로 대체.
   keys.txt, CTR 카운터 파일, 로그 파일을 실행 파일 위치에 고정하는 데 사용.
   잘못된 ctr_state 파일을 읽고 쓰면 송신자/수신자 카운터 어긋나므로 유의. (카운터 전송하지 않으므로) */
void exe_relative_path(const char *argv0, const char *filename, char *out, size_t out_size);

/* keys.txt를 다음 순서로 탐색해 key_store_load_file()로 불러옴:
   cwd "keys.txt" -> (argv0이 NULL이 아니면) 실행 파일 옆의 "keys.txt" ->
   "keymgmt/keys.txt" -> "security/keymgmt/keys.txt" -> "../keymgmt/keys.txt".
   실행 파일 위치를 모르는 호출자(예: 인터랙티브 도구)는 argv0에 NULL을 넘기면 되며,
   그 경우 해당 후보만 건너뜀. 불러온 키 항목 수(>0)를 반환하며, 전부 실패하면 <=0을 반환. */
int demo_load_keys(const char *argv0);

#endif /* SECURITY_DEMO_KEY_PATHS_H */