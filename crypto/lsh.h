/* LSH-256 */
#ifndef SECURITY_CRYPTO_LSH_H
#define SECURITY_CRYPTO_LSH_H

#include <stddef.h>
#include <stdint.h>
#include "lsh_ref/include/lsh.h"

#define LSH256_DIGEST_SIZE 32

typedef union LSH_Context lsh256_ctx_t;

void lsh256_init(lsh256_ctx_t *ctx);
void lsh256_update(lsh256_ctx_t *ctx, const uint8_t *data, size_t len);
void lsh256_final(lsh256_ctx_t *ctx, uint8_t digest[LSH256_DIGEST_SIZE]);

/* Single-shot convenience wrapper over init/update/final. */
void lsh256(const uint8_t *data, size_t len, uint8_t digest[LSH256_DIGEST_SIZE]);

#endif /* SECURITY_CRYPTO_LSH_H */
