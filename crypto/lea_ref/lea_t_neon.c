#include "lea.h"
#include "lea_locl.h"
#include "arm_arch.h" /* defines __ARMEL__/__ARMEB__ for __aarch64__ -- without this,
                          lea_neon.h's #ifdef __ARMEL__ guards never fire on AArch64
                          (that macro is otherwise only set by GCC for 32-bit ARM), so
                          every load/store in lea_neon.h silently falls through to its
                          byte-swap-capable fallback path -- which has an unrelated
                          argument-order mismatch between lea_locl.h's little-endian and
                          big-endian ctow/wtoc definitions and fails to even compile on
                          real little-endian AArch64 (see arm64cpuid.S, which already
                          includes arm_arch.h for the same reason). */

#ifdef COMPILE_NEON

#if !defined(__ARM_NEON__)
#error "turn on NEON flag for lea_t_neon.c"
#endif


#include <arm_neon.h>


#define MAX_BLK 4
#define SIMD_TYPE neon

#define lea_encrypt_1block lea_encrypt
#define lea_decrypt_1block lea_decrypt

#include "lea_neon.h"

#include "lea_key.h"

#include "lea_ecb.h"
#include "lea_cbc.h"
#include "lea_ctr.h"
#include "lea_cfb.h"
#include "lea_ofb.h"

#include "lea_cmac.h"

#include "lea_ccm.h"
#include "lea_gcm.h"

#endif
