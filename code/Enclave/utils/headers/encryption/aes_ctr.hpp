#ifndef _AES_CTR_HPP_
#define _AES_CTR_HPP_

#include "../../../../flag.h"
#if EMULATING
#   include "../../../../tests/SGX_Emulator/sgx_tcrypto.hpp"
#   include "../../../../tests/SGX_Emulator/sgx_trts.hpp"
#else
#   include "sgx_tcrypto.h"
#   include "sgx_trts.h"
#endif

#include <cstring>


#define AES_CTR_COUNTER_SIZE    16

typedef struct _lauxus_ctr_t {
  sgx_aes_ctr_128bit_key_t key;
  uint8_t ctr[AES_CTR_COUNTER_SIZE];
} lauxus_ctr_t;


void lauxus_random_ctr(lauxus_ctr_t *ctx);

int lauxus_ctr_encrypt(lauxus_ctr_t *ctx, const uint8_t *p_plain, const uint32_t plain_len,
                uint8_t *p_cypher);

int lauxus_ctr_decrypt(lauxus_ctr_t *ctx, const uint8_t *p_cypher, const uint32_t cypher_len,
                uint8_t *p_plain);


#endif /*_AES_CTR_HPP_*/
