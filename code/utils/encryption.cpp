#include "../utils/encryption.hpp"

#include "../flag.h"
#if EMULATING
#  include "../tests/SGX_Emulator/sgx_tcrypto.hpp"
#  include "../tests/SGX_Emulator/sgx_trts.hpp"
#  include "../tests/SGX_Emulator/sgx_error.hpp"
#else
#   include "sgx_tcrypto.h"
#   include "sgx_trts.h"
#   include "sgx_error.h"
#endif

#include <string>
#include <cstring>


///////////////////////////////////////////////////////////////////////////////
////////////////////////    AES_CTR_context     ///////////////////////////////
///////////////////////////////////////////////////////////////////////////////
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



///////////////////////////////////////////////////////////////////////////////
////////////////////////    AES_GCM_context     ///////////////////////////////
///////////////////////////////////////////////////////////////////////////////
AES_GCM_context::AES_GCM_context() {
  this->p_key = (sgx_aes_gcm_128bit_key_t*) malloc(16);
  this->p_iv = (uint8_t*) malloc(12);
  this->p_mac = (sgx_aes_gcm_128bit_tag_t*) calloc(1, 16);

  sgx_read_rand((uint8_t*)this->p_key, 16);
  sgx_read_rand((uint8_t*)this->p_iv, 12);
}

AES_GCM_context::~AES_GCM_context() {
  free(this->p_key);
  free(this->p_iv);
  free(this->p_mac);
}


int AES_GCM_context::dump(const size_t buffer_size, char *buffer) {
  if (buffer_size < 44)
    return -1;

  std::memcpy(buffer, this->p_key, 16);
  std::memcpy(buffer+16, this->p_iv, 12);
  std::memcpy(buffer+28, this->p_mac, 16);
  return 44;
}
int AES_GCM_context::dump_without_mac(const size_t buffer_size, char *buffer) {
  if (buffer_size < 28)
    return -1;

  std::memcpy(buffer, this->p_key, 16);
  std::memcpy(buffer+16, this->p_iv, 12);
  return 28;
}

int AES_GCM_context::load(const size_t buffer_size, const char *buffer) {
  if (buffer_size < 44)
    return -1;
  std::memcpy(this->p_key, buffer, 16);
  std::memcpy(this->p_iv, buffer+16, 12);
  std::memcpy(this->p_mac, buffer+28, 16);
  return 44;
}
int AES_GCM_context::load_without_mac(const size_t buffer_size, const char *buffer) {
  if (buffer_size < 28)
    return -1;
  std::memcpy(this->p_key, buffer, 16);
  std::memcpy(this->p_iv, buffer+16, 12);
  return 28;
}


bool AES_GCM_context::equals(AES_GCM_context *other) {
  return std::memcmp(this->p_key, other->p_key, sizeof(sgx_aes_gcm_128bit_key_t)) == 0 &&
        std::memcmp(this->p_iv, other->p_iv, 12) == 0 &&
        std::memcmp(this->p_mac, other->p_mac, sizeof(sgx_aes_gcm_128bit_tag_t)) == 0;
}


int AES_GCM_context::encrypt(const uint8_t *p_plain, const uint32_t plain_len,
                                const uint8_t *p_aad, const uint32_t aad_len, uint8_t *p_cypher) {
  if (sgx_rijndael128GCM_encrypt(this->p_key, p_plain, plain_len, p_cypher, this->p_iv, 12,
                                  p_aad, aad_len, this->p_mac) != SGX_SUCCESS) {
    return -1;
  }
  return plain_len;
}

int AES_GCM_context::decrypt(const uint8_t *p_cypher, const uint32_t cypher_len,
                                const uint8_t *p_aad, const uint32_t aad_len, uint8_t *p_plain) {
  if (sgx_rijndael128GCM_decrypt(this->p_key, p_cypher, cypher_len, p_plain, this->p_iv, 12,
                                  p_aad, aad_len, this->p_mac) != SGX_SUCCESS) {
    return -1;
  }
  return cypher_len;
}

int AES_GCM_context::decrypt_with_mac(const uint8_t *p_cypher, const uint32_t cypher_len,
                                const uint8_t *p_aad, const uint32_t aad_len, uint8_t *p_plain,
                                const sgx_aes_gcm_128bit_tag_t *mac) {
  if (sgx_rijndael128GCM_decrypt(this->p_key, p_cypher, cypher_len, p_plain, this->p_iv, 12,
                                  p_aad, aad_len, mac) != SGX_SUCCESS) {
    return -1;
  }
  return cypher_len;
}


// Static functions
size_t AES_GCM_context::size() { return 44; }
size_t AES_GCM_context::size_without_mac() { return 28; }
