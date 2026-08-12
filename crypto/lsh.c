#include "lsh.h"

/* lsh_update()/lsh_digest()는 길이를 바이트가 아니라 비트 단위로 받음 */

void lsh256_init(lsh256_ctx_t *ctx)
{
    lsh_init(ctx, LSH_TYPE_256);
}

void lsh256_update(lsh256_ctx_t *ctx, const uint8_t *data, size_t len)
{
    lsh_update(ctx, data, len * 8);
}

void lsh256_final(lsh256_ctx_t *ctx, uint8_t digest[LSH256_DIGEST_SIZE])
{
    lsh_final(ctx, digest);
}

void lsh256(const uint8_t *data, size_t len, uint8_t digest[LSH256_DIGEST_SIZE])
{
    lsh_digest(LSH_TYPE_256, data, len * 8, digest);
}
