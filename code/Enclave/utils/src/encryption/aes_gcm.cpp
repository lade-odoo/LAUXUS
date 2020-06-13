#include "../../headers/encryption/aes_gcm.hpp"


void lauxus_random_gcm(lauxus_gcm_t *ctx) {
  sgx_read_rand((uint8_t*)&ctx->key, sizeof(sgx_aes_gcm_128bit_key_t));
  sgx_read_rand(ctx->iv, AES_GCM_IV_SIZE);
}


int lauxus_gcm_encrypt(lauxus_gcm_t *ctx, const uint8_t *p_plain, const uint32_t plain_len,
                const uint8_t *p_aad, const uint32_t aad_len, uint8_t *p_cypher) {

  if (sgx_rijndael128GCM_encrypt(&ctx->key, p_plain, plain_len, p_cypher, ctx->iv, AES_GCM_IV_SIZE,
                    p_aad, aad_len, &ctx->mac) != SGX_SUCCESS) {
    return -1;
  }
  return plain_len;
}

int lauxus_gcm_decrypt(lauxus_gcm_t *ctx, const uint8_t *p_cypher, const uint32_t cypher_len,
                const uint8_t *p_aad, const uint32_t aad_len, uint8_t *p_plain) {

  if (sgx_rijndael128GCM_decrypt(&ctx->key, p_cypher, cypher_len, p_plain, ctx->iv, AES_GCM_IV_SIZE,
                    p_aad, aad_len, &ctx->mac) != SGX_SUCCESS) {
    return -1;
  }
  return cypher_len;
}
