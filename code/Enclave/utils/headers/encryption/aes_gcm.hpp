#ifndef _AES_GCM_HPP_
#define _AES_GCM_HPP_

#include "../../../../flag.h"
#if EMULATING
#   include "../../../../tests/SGX_Emulator/sgx_tcrypto.hpp"
#   include "../../../../tests/SGX_Emulator/sgx_trts.hpp"
#else
#   include "sgx_tcrypto.h"
#   include "sgx_trts.h"
#endif


#define AES_GCM_IV_SIZE    12

typedef struct _lauxus_gcm_t {
  sgx_aes_gcm_128bit_key_t key;
  uint8_t iv[AES_GCM_IV_SIZE];
  sgx_aes_gcm_128bit_tag_t mac;
} lauxus_gcm_t;


void lauxus_random_gcm(lauxus_gcm_t *ctx);

int lauxus_gcm_encrypt(lauxus_gcm_t *ctx, const uint8_t *p_plain, const uint32_t plain_len,
                const uint8_t *p_aad, const uint32_t aad_len, uint8_t *p_cypher);

int lauxus_gcm_decrypt(lauxus_gcm_t *ctx, const uint8_t *p_cypher, const uint32_t cypher_len,
                const uint8_t *p_aad, const uint32_t aad_len, uint8_t *p_plain);


#endif /*_AES_GCM_HPP_*/
