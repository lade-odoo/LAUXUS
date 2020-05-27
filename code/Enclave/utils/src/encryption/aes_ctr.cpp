#include "../../headers/encryption/aes_ctr.hpp"


void lauxus_random_ctr(lauxus_ctr_t *ctx) {
  sgx_read_rand((uint8_t*)&ctx->key, sizeof(sgx_aes_ctr_128bit_key_t));
  sgx_read_rand(ctx->ctr, AES_CTR_COUNTER_SIZE);
}

int lauxus_ctr_encrypt(lauxus_ctr_t *ctx, const uint8_t *p_plain, const uint32_t plain_len,
                uint8_t *p_cypher) {
  uint8_t ctr[AES_CTR_COUNTER_SIZE];

  std::memcpy(ctr, ctx->ctr, AES_CTR_COUNTER_SIZE);
  if (sgx_aes_ctr_encrypt(&ctx->key, p_plain, plain_len, ctr, 64, p_cypher) != SGX_SUCCESS)
    return -1;
  return plain_len;
}

int lauxus_ctr_decrypt(lauxus_ctr_t *ctx, const uint8_t *p_cypher, const uint32_t cypher_len,
                uint8_t *p_plain) {
  uint8_t ctr[AES_CTR_COUNTER_SIZE];

  std::memcpy(ctr, ctx->ctr, AES_CTR_COUNTER_SIZE);
  if (sgx_aes_ctr_decrypt(&ctx->key, p_cypher, cypher_len, ctr, 64, p_plain) != SGX_SUCCESS)
    return -1;
  return cypher_len;
}
