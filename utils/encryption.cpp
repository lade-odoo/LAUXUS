#include "../utils/encryption.hpp"

#include <string>
#include <cstring>



///////////////////////////////////////////////////////////////////////////////
////////////////////////    AES_CTR_context     ///////////////////////////////
///////////////////////////////////////////////////////////////////////////////
AES_CTR_context::AES_CTR_context() {
  this->p_key = (sgx_aes_ctr_128bit_key_t*) malloc(16);
  this->p_ctr = (uint8_t*) malloc(16);

  uint8_t key[] = {0x00, 0x01, 0x02, 0x03,
                  0x04, 0x05, 0x06, 0x07,
                  0x08, 0x09, 0x0a, 0x0b,
                  0x0c, 0x0d, 0x0e, 0x0f};
  uint8_t ctr0[] = {0xff, 0xee, 0xdd, 0xcc,
                  0xbb, 0xaa, 0x99, 0x88,
                  0x77, 0x66, 0x55, 0x44,
                  0x33, 0x22, 0x11, 0x00};
  std::memcpy(this->p_key, key, 16);
  std::memcpy(this->p_ctr, ctr0, 16);
}

AES_CTR_context::~AES_CTR_context() {
  free(this->p_key);
  free(this->p_ctr);
}


size_t AES_CTR_context::dump(const size_t offset, char *buffer) {
  std::memcpy(buffer + offset, this->p_key, 16);
  std::memcpy(buffer + offset + 16, this->p_ctr, 16);
  return 32;
}


size_t AES_CTR_context::encrypt(const uint8_t *p_src, const uint32_t src_len, uint8_t *p_dst) {
  uint8_t ctr[16];
  std::memcpy(ctr, this->p_ctr, 16);
  sgx_aes_ctr_encrypt(this->p_key, p_src, src_len, ctr, 64, p_dst);
  return src_len;
}

size_t AES_CTR_context::decrypt(const uint8_t *p_src, const uint32_t src_len, uint8_t *p_dst) {
  uint8_t ctr[16];
  std::memcpy(ctr, this->p_ctr, 16);
  sgx_aes_ctr_decrypt(this->p_key, p_src, src_len, ctr, 64, p_dst);
  return src_len;
}


// Static function
int AES_CTR_context::size() {
  return 16 + 16;
}
