#include "../utils/encryption.hpp"

#include "sgx_tcrypto.h"
#include "sgx_trts.h"
#include "sgx_error.h"
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
  this->p_mac = (sgx_aes_gcm_128bit_tag_t*) malloc(16);;

  sgx_read_rand((uint8_t*)this->p_key, 16);
  sgx_read_rand((uint8_t*)this->p_iv, 12);
}

AES_GCM_context::~AES_GCM_context() {
  free(this->p_key);
  free(this->p_iv);
  if (this->p_mac != NULL)
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

int AES_GCM_context::encrypt_key_and_dump(AES_GCM_context *root_key, const size_t buffer_size, char *buffer) {
  if (buffer_size < 44)
    return -1;

  if (root_key->encrypt((uint8_t*)this->p_key, 16, (uint8_t*)NULL, 0, (uint8_t*)buffer) < 0)
    return -1;
  std::memcpy(buffer+16, this->p_iv, 12);
  std::memcpy(buffer+28, this->p_mac, 16);
  return 44;
}

int AES_GCM_context::dump_aad(const size_t buffer_size, char *buffer) {
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

int AES_GCM_context::decrypt_key_and_load(AES_GCM_context *root_key, const char* buffer) {
  if (root_key->decrypt((uint8_t*)buffer, 16, (uint8_t*)NULL, 0, (uint8_t*)this->p_key) < 0)
    return -1;
  std::memcpy(this->p_iv, buffer+16, 12);
  std::memcpy(this->p_mac, buffer+28, 16);
  return 44;
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
  if (sgx_rijndael128GCM_encrypt(this->p_key, p_cypher, cypher_len, p_plain, this->p_iv, 12,
                                  p_aad, aad_len, this->p_mac) != SGX_SUCCESS) {
    return -1;
  }
  return cypher_len;
}


// Static functions
size_t AES_GCM_context::size() { return 44; }
size_t AES_GCM_context::size_aad() { return 28; }
