#include "metadata.hpp"
#include "encryption/aes_gcm.hpp"

#include "../flag.h"
#if EMULATING
#  include "../tests/SGX_Emulator/sgx_trts.hpp"
#else
#   include "sgx_trts.h"
#endif

#include <string>
#include <cstring>
#include <vector>

using namespace std;



Metadata::Metadata(AES_GCM_context *root_key) {
  this->root_key = root_key;
  this->aes_gcm_ctx = new AES_GCM_context();
}

Metadata::~Metadata() {
  delete this->aes_gcm_ctx;
}


bool Metadata::equals(Metadata *other) {
  return this->root_key->equals(other->root_key) &&
          this->aes_gcm_ctx->equals(other->aes_gcm_ctx);
}


void Metadata::update_crypto_ctx() {
  this->aes_gcm_ctx->update_iv();
}


size_t Metadata::e_size() {
  size_t mac_size = AES_GCM_context::size() - AES_GCM_context::size_without_mac();
  return this->p_preamble_size() + mac_size + this->e_crypto_size() + this->e_sensitive_size();
}

int Metadata::e_dump(const size_t buffer_size, char *buffer) {
  if (buffer_size < this->e_size())
    return -1;

  int written = 0;

  // preamble section
  int preamble_size = this->p_dump_preamble(this->p_preamble_size(), buffer);
  if (preamble_size < 0)
    return -1;
  written += preamble_size;

  // encrypting the sensitive section
  int sensitive_size = this->e_sensitive_size();
  int sensitive_offset = buffer_size - sensitive_size;
  if (this->e_dump_sensitive(sensitive_size, buffer+sensitive_offset) != sensitive_size)
    return -1;
  written += sensitive_size;

  // crypto context
  int crypto_size = this->e_crypto_size();
  int crypto_offset = buffer_size - sensitive_size - crypto_size;
  if (this->e_dump_crypto(crypto_size, buffer+crypto_offset) != crypto_size)
    return -1;
  written += crypto_size;

  // dump mac of root key
  int mac_size = AES_GCM_context::size() - AES_GCM_context::size_without_mac();
  int mac_offset = buffer_size - sensitive_size - crypto_size - mac_size;
  memcpy(buffer+mac_offset, this->root_key->p_mac, mac_size);
  written += mac_size;

  return written;
}

int Metadata::e_load(const size_t buffer_size, const char *buffer) {
  int read = 0;

  // preamble section
  int preamble_size = this->p_load_preamble(buffer_size, buffer);
  if (preamble_size < 0)
    return -1;
  read += preamble_size;

  // MAC of the encryption of the crypto context
  int mac_size = AES_GCM_context::size() - AES_GCM_context::size_without_mac();
  int mac_offset = preamble_size;
  if ((int)(buffer_size-read) < mac_size)
    return -1;
  memcpy(this->root_key->p_mac, buffer+mac_offset, mac_size);
  read += mac_size;

  // crypto context
  int crypto_size = this->e_load_crypto(buffer_size-read, buffer+read);
  if (crypto_size < 0)
    return -1;
  read += crypto_size;

  // sensitive informations section
  int sensitive_size = this->e_load_sensitive(buffer_size-read, buffer+read);
  if (sensitive_size < 0)
    return -1;
  read += sensitive_size;

  return read;
}


size_t Metadata::e_crypto_size() {
  return sizeof(int) + AES_GCM_context::size();
}

int Metadata::e_dump_crypto(const size_t buffer_size, char *buffer) {
  if (buffer_size < this->e_crypto_size())
    return -1;

  size_t plain_size = AES_GCM_context::size();
  char plain[plain_size];
  this->aes_gcm_ctx->dump(plain_size, plain);

  int cypher_size = this->root_key->encrypt((uint8_t*)plain, plain_size, NULL, 0, (uint8_t*)buffer+sizeof(int));
  if (cypher_size < 0)
    return -1;

  memcpy(buffer, &cypher_size, sizeof(int));
  return sizeof(int) + cypher_size;
}

int Metadata::e_load_crypto(const size_t buffer_size, const char *buffer) {
  if (buffer_size < sizeof(int))
    return -1;

  int cypher_size = 0;
  memcpy(&cypher_size, buffer, sizeof(int));
  if ((int)(buffer_size-sizeof(int)) < cypher_size)
    return -1;

  size_t plain_size = AES_GCM_context::size();
  char plain[plain_size];
  int decrypted = this->root_key->decrypt((uint8_t*)buffer+sizeof(int), cypher_size, NULL, 0, (uint8_t*)plain);
  if (decrypted != cypher_size)
    return -1;
  if (this->aes_gcm_ctx->load(plain_size, plain) != decrypted)
    return -1;

  return sizeof(int) + decrypted;
}


size_t Metadata::e_sensitive_size() {
  return sizeof(int) + this->p_sensitive_size();
}

int Metadata::e_dump_sensitive(const size_t buffer_size, char *buffer) {
  if (buffer_size < this->e_sensitive_size())
    return -1;

  size_t plain_size = this->p_sensitive_size();
  char plain[plain_size];
  size_t aad_size = this->p_preamble_size();
  char aad[aad_size];

  if (this->p_dump_sensitive(plain_size, plain) < 0 || this->p_dump_preamble(aad_size, aad) < 0)
    return -1;

  int cypher_size = this->aes_gcm_ctx->encrypt((uint8_t*)plain, plain_size, (uint8_t*)aad, aad_size, (uint8_t*)buffer+sizeof(int));
  if (cypher_size < 0)
    return -1;

  memcpy(buffer, &cypher_size, sizeof(int));
  return sizeof(int) + cypher_size;
}

int Metadata::e_load_sensitive(const size_t buffer_size, const char *buffer) {
  if (buffer_size < sizeof(int))
    return -1;

  int cypher_size = 0;
  memcpy(&cypher_size, buffer, sizeof(int));
  if ((int)(buffer_size-sizeof(int)) < cypher_size)
    return -1;

  size_t plain_size = cypher_size;
  char plain[plain_size];
  size_t aad_size = this->p_preamble_size();
  char aad[aad_size];

  if (this->p_dump_preamble(aad_size, aad) < 0)
    return -1;

  int decrypted = this->aes_gcm_ctx->decrypt((uint8_t*)buffer+sizeof(int), cypher_size, (uint8_t*)aad, aad_size, (uint8_t*)plain);
  if (decrypted != cypher_size)
    return -1;
  if (this->p_load_sensitive(plain_size, plain) != decrypted)
    return -1;

  return sizeof(int) + decrypted;
}
