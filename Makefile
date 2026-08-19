# Builds secure_send_demo / secure_recv_demo for the real target (Raspberry
# Pi 5 / CM5, aarch64) plus a couple of secondary targets. Just run `make`
# on the Pi.
#
# The LEA cipher's vendored reference code (crypto/lea_ref/) ships separate
# translation units per SIMD backend (x86 SSE2/AVX2/XOP/PCLMUL, ARM NEON,
# portable generic/fallback) selected at runtime by lea_base.c's
# init_simd() -- but the RIGHT translation units still have to be compiled
# and linked in for the target architecture, since the unused ones won't
# even compile (x86 intrinsics on ARM, and vice versa). ARCH below picks
# that file list.
#
# NEON note: lea_t_neon.c guards itself with `#if !defined(__ARM_NEON__)`,
# but GCC/Clang on aarch64 define __ARM_NEON (no trailing underscore) --
# __ARM_NEON__ is the older armv7 spelling. Without -D__ARM_NEON__=1 that
# guard's #error fires on a from-scratch aarch64 build even though NEON is
# baseline on aarch64 and the file would otherwise compile fine.
#
# make NO_NEON=1   -- fall back to the portable generic C path if the NEON
#                     build gives you trouble on-device; slower, zero SIMD.

CC      ?= gcc
CFLAGS  ?= -O2 -Wall
ARCH    := $(shell uname -m)

SEC_SRCS = framing/secure_frame.c \
           keymgmt/key_store.c \
           keymgmt/ctr_state.c \
           crypto/lea.c \
           crypto/lea_ctr.c \
           crypto/hmac_lsh.c \
           crypto/lsh_ref/src/lsh.c \
           crypto/lsh_ref/src/lsh256.c \
           crypto/lsh_ref/src/lsh512.c \
           crypto/lsh_ref/src/hmac.c

LEA_REF_COMMON = crypto/lea_ref/lea_base.c \
                 crypto/lea_ref/lea_core.c \
                 crypto/lea_ref/lea_online.c \
                 crypto/lea_ref/lea_gcm_generic.c \
                 crypto/lea_ref/lea_t_fallback.c \
                 crypto/lea_ref/lea_t_generic.c

ifeq ($(ARCH),aarch64)
  ifdef NO_NEON
    LEA_REF_ARCH = crypto/lea_ref/cpu_info_arm.c crypto/lea_ref/arm64cpuid.S
    ARCH_CFLAGS  = -DNO_NEON
  else
    LEA_REF_ARCH = crypto/lea_ref/cpu_info_arm.c crypto/lea_ref/arm64cpuid.S crypto/lea_ref/lea_t_neon.c
    ARCH_CFLAGS  = -D__ARM_NEON__=1
  endif
else ifeq ($(ARCH),armv7l)
  ifdef NO_NEON
    LEA_REF_ARCH = crypto/lea_ref/cpu_info_arm.c crypto/lea_ref/armv4cpuid.S
    ARCH_CFLAGS  = -DNO_NEON
  else
    LEA_REF_ARCH = crypto/lea_ref/cpu_info_arm.c crypto/lea_ref/armv4cpuid.S crypto/lea_ref/lea_t_neon.c
    ARCH_CFLAGS  = -mfpu=neon -D__ARM_NEON__=1
  endif
else
  # Not a Pi -- e.g. running this Makefile on an x86_64 dev box to sanity
  # check the non-crypto plumbing compiles. Deliberately generic-only: the
  # x86 SIMD backends (lea_t_xop.c etc.) are untested from this repo's own
  # build process (only ever linked here from someone else's prebuilt
  # .o files) and not worth risking on a path nobody asked for.
  LEA_REF_ARCH = crypto/lea_ref/cpu_info_ia32.c
  ARCH_CFLAGS  = -DNO_AVX2 -DNO_XOP -DNO_PCLMUL -DNO_SSE2
endif

# key_paths.c (exe-relative path + keys.txt search) is needed by all three demo
# binaries, so it rides in DEMO_COMMON/LIB_OBJS like serial_port.c already does.
# demo_log.c (file logging + its print_hex) is only used by secure_send_demo and
# secure_recv_demo -- main.c has its own console-only print_hex and no log file
# -- so it gets its own object list linked into just those two targets, keeping
# it out of secure_demo's binary.
# modbus_pdu.c (function-code request/response building + the demo register/coil
# model) is needed by secure_demo (builds requests as master, responses as slave)
# and secure_recv_demo (responses as slave) -- but not secure_send_demo, which
# never acts as slave and keeps its own fixed function-0x10 frame-size sweep.
# modbus_pdu_selftest.c (the modbus_pdu_self_test() cases) rides along with it --
# secure_demo's self-test menu option calls it, and it's the same object the
# `test` target below links into the standalone test_modbus_response runner.
DEMO_COMMON = demo/serial_port.c demo/key_paths.c
DEMO_LOG    = demo/demo_log.c
MODBUS_PDU  = modbus/modbus_pdu.c modbus/modbus_pdu_selftest.c

LIB_SRCS  = $(SEC_SRCS) $(LEA_REF_COMMON) $(LEA_REF_ARCH) $(DEMO_COMMON)
LIB_OBJS  = $(patsubst %.c,%.o,$(patsubst %.S,%.o,$(LIB_SRCS)))
DEMO_LOG_OBJS    = $(patsubst %.c,%.o,$(DEMO_LOG))
MODBUS_PDU_OBJS  = $(patsubst %.c,%.o,$(MODBUS_PDU))

.PHONY: all clean test
all: secure_send_demo secure_recv_demo secure_demo

# modbus_pdu.c의 순수 로직(암호화/시리얼 무관)만 도는 유닛 테스트 -- 실패 시
# test_modbus_response 자체가 0이 아닌 값을 반환해 make도 실패로 표시한다.
test: demo/test_modbus_response
	demo/test_modbus_response

demo/test_modbus_response: demo/test_modbus_response.c $(MODBUS_PDU)
	$(CC) $(CFLAGS) -o $@ demo/test_modbus_response.c $(MODBUS_PDU)

secure_send_demo: demo/secure_send_demo.o $(LIB_OBJS) $(DEMO_LOG_OBJS)
	$(CC) $^ -o $@

secure_recv_demo: demo/secure_recv_demo.o $(LIB_OBJS) $(DEMO_LOG_OBJS) $(MODBUS_PDU_OBJS)
	$(CC) $^ -o $@

secure_demo: demo/main.o $(LIB_OBJS) $(MODBUS_PDU_OBJS)
	$(CC) $^ -o $@

%.o: %.c
	$(CC) $(CFLAGS) $(ARCH_CFLAGS) -c $< -o $@

%.o: %.S
	$(CC) $(CFLAGS) $(ARCH_CFLAGS) -c $< -o $@

clean:
	rm -f secure_send_demo secure_recv_demo secure_demo demo/test_modbus_response demo/secure_send_demo.o demo/secure_recv_demo.o demo/main.o $(LIB_OBJS) $(DEMO_LOG_OBJS) $(MODBUS_PDU_OBJS)
