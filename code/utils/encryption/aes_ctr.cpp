#include "../encryption/aes_ctr.hpp"

#include "../../flag.h"
#if EMULATING
#  include "../../tests/SGX_Emulator/sgx_tcrypto.hpp"
#  include "../../tests/SGX_Emulator/sgx_trts.hpp"
#  include "../../tests/SGX_Emulator/sgx_error.hpp"
#else
#   include "sgx_tcrypto.h"
#   include "sgx_trts.h"
#   include "sgx_error.h"
#endif

#include <string>
#include <cstring>



AES_CTR_context::AES_CTR_context() {
  this->p_key = (sgx_aes_ctr_128bit_key_t*) malloc(16);
  this->p_ctr = (uint8_t*) malloc(16);

  sgx_read_rand((uint8_t*)this->p_key, 16);
  sgx_read_rand((uint8_t*)this->p_ctr, 16);
}

AES_CTR_context::~AES_CTR_context() {
  free(this->p_key);
  free(this->p_ctr);
}


void AES_CTR_context::update_iv() {
  sgx_read_rand((uint8_t*)this->p_ctr, 16);
}


int AES_CTR_context::dump(const size_t buffer_size, char *buffer) {
  if (buffer_size < 32)
    return -1;

  std::memcpy(buffer, this->p_key, 16);
  std::memcpy(buffer + 16, this->p_ctr, 16);
  return 32;
}

int AES_CTR_context::load(const size_t buffer_size, const char *buffer) {
  if (buffer_size < 32)
    return -1;

  std::memcpy(this->p_key, buffer, 16);
  std::memcpy(this->p_ctr, buffer+16, 16);
  return 32;
}


bool AES_CTR_context::equals(AES_CTR_context *other) {
  return std::memcmp(this->p_key, other->p_key, sizeof(sgx_aes_ctr_128bit_key_t)) == 0 &&
        std::memcmp(this->p_ctr, other->p_ctr, 16) == 0;
}


int AES_CTR_context::encrypt(const uint8_t *p_plain, const uint32_t plain_len, uint8_t *p_cypher) {
  uint8_t ctr[16];
  std::memcpy(ctr, this->p_ctr, 16);
  if (sgx_aes_ctr_encrypt(this->p_key, p_plain, plain_len, ctr, 64, p_cypher) != SGX_SUCCESS)
    return -1;
  return plain_len;
}

int AES_CTR_context::decrypt(const uint8_t *p_cypher, const uint32_t cypher_len, uint8_t *p_plain) {
  uint8_t ctr[16];
  std::memcpy(ctr, this->p_ctr, 16);
  if (sgx_aes_ctr_decrypt(this->p_key, p_cypher, cypher_len, ctr, 64, p_plain) != SGX_SUCCESS)
    return -1;
  return cypher_len;
}


// Static functions
size_t AES_CTR_context::size() { return 32; }
