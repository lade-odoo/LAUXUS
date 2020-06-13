#include "../../headers/encryption/metadata.hpp"


Metadata::Metadata(lauxus_gcm_t *root_key) {
  this->root_key = root_key;
  this->aes_gcm_ctx = (lauxus_gcm_t*) malloc(sizeof(lauxus_gcm_t));
}
Metadata::~Metadata() {
  free(this->aes_gcm_ctx);
}

bool Metadata::equals(Metadata *other) {
  return memcmp(this->root_key, other->root_key, sizeof(lauxus_gcm_t)) == 0 &&
          memcmp(this->aes_gcm_ctx, other->aes_gcm_ctx, sizeof(lauxus_gcm_t)) == 0;
}

void Metadata::update_crypto_ctx() {
  sgx_read_rand(this->aes_gcm_ctx->iv, AES_GCM_IV_SIZE);
}


size_t Metadata::e_size() {
  return sizeof(sgx_aes_gcm_128bit_tag_t) + this->p_preamble_size() + this->e_crypto_size() + this->e_sensitive_size();
}

int Metadata::e_dump(const size_t buffer_size, uint8_t *buffer) {
  size_t written = 0;
  if (buffer_size < this->e_size())
    return -1;

  // preamble section
  int preamble_size = this->p_dump_preamble(this->p_preamble_size(), buffer);
  if (preamble_size < 0)
    return -1;
  written += preamble_size;

  // encrypting the sensitive section
  int sensitive_size = this->e_sensitive_size();
  size_t sensitive_offset = buffer_size - sensitive_size;
  if (this->e_dump_sensitive(sensitive_size, buffer+sensitive_offset) != sensitive_size)
    return -1;
  written += sensitive_size;

  // crypto context
  int crypto_size = this->e_crypto_size();
  size_t crypto_offset = buffer_size - sensitive_size - crypto_size;
  if (this->e_dump_crypto(crypto_size, buffer+crypto_offset) != crypto_size)
    return -1;
  written += crypto_size;

  // dump mac of root key
  size_t mac_size = sizeof(sgx_aes_gcm_128bit_tag_t);
  size_t mac_offset = buffer_size - sensitive_size - crypto_size - mac_size;
  memcpy(buffer+mac_offset, &this->root_key->mac, mac_size);
  written += mac_size;

  return written;
}

int Metadata::e_load(const size_t buffer_size, const uint8_t *buffer) {
  size_t read = 0;

  // preamble section
  int preamble_size = this->p_load_preamble(buffer_size, buffer);
  if (preamble_size < 0)
    return -1;
  read += preamble_size;

  // MAC of the encryption of the crypto context
  size_t mac_size = sizeof(sgx_aes_gcm_128bit_tag_t);
  size_t mac_offset = preamble_size;
  if (buffer_size-read < mac_size)
    return -1;
  memcpy(&this->root_key->mac, buffer+mac_offset, mac_size);
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
  return sizeof(size_t) + sizeof(lauxus_gcm_t);
}

int Metadata::e_dump_crypto(const size_t buffer_size, uint8_t *buffer) {
  int written = 0;
  if (buffer_size < this->e_crypto_size())
    return -1;

  size_t plain_size = sizeof(lauxus_gcm_t);
  uint8_t plain[plain_size];
  memcpy(plain, this->aes_gcm_ctx, plain_size);

  int cypher_size = lauxus_gcm_encrypt(this->root_key, plain, plain_size, NULL, 0, buffer+sizeof(size_t));
  if (cypher_size < 0)
    return -1;
  written += cypher_size;

  size_t tmp = cypher_size;
  memcpy(buffer, &tmp, sizeof(size_t));
  written += sizeof(size_t);
  return written;
}

int Metadata::e_load_crypto(const size_t buffer_size, const uint8_t *buffer) {
  size_t read = 0;
  if (buffer_size < sizeof(size_t))
    return -1;

  size_t cypher_size = 0;
  memcpy(&cypher_size, buffer, sizeof(size_t)); read += sizeof(size_t);
  if (buffer_size-read < cypher_size)
    return -1;

  size_t plain_size = sizeof(lauxus_gcm_t);
  uint8_t plain[plain_size];
  int decrypted = lauxus_gcm_decrypt(this->root_key, buffer+read, cypher_size, NULL, 0, plain);
  if ((size_t)decrypted != cypher_size)
    return -1;
  read += decrypted;

  memcpy(this->aes_gcm_ctx, plain, plain_size);
  return read;
}


size_t Metadata::e_sensitive_size() {
  return sizeof(size_t) + this->p_sensitive_size();
}

int Metadata::e_dump_sensitive(const size_t buffer_size, uint8_t *buffer) {
  size_t written = 0;
  if (buffer_size < this->e_sensitive_size())
    return -1;

  size_t plain_size = this->p_sensitive_size();
  uint8_t plain[plain_size];
  size_t aad_size = this->p_preamble_size();
  uint8_t aad[aad_size];

  if (this->p_dump_sensitive(plain_size, plain) < 0 || this->p_dump_preamble(aad_size, aad) < 0)
    return -1;

  int cypher_size = lauxus_gcm_encrypt(this->aes_gcm_ctx, plain, plain_size, aad, aad_size, buffer+sizeof(size_t));
  if (cypher_size < 0)
    return -1;
  written += cypher_size;

  size_t tmp = cypher_size;
  memcpy(buffer, &tmp, sizeof(size_t));
  written += sizeof(size_t);
  return written;
}

int Metadata::e_load_sensitive(const size_t buffer_size, const uint8_t *buffer) {
  size_t read = 0;
  if (buffer_size < sizeof(size_t))
    return -1;

  size_t cypher_size = 0;
  memcpy(&cypher_size, buffer, sizeof(size_t)); read += sizeof(size_t);
  if (buffer_size-read < cypher_size)
    return -1;

  size_t plain_size = cypher_size;
  uint8_t plain[plain_size];
  size_t aad_size = this->p_preamble_size();
  uint8_t aad[aad_size];

  if (this->p_dump_preamble(aad_size, aad) < 0)
    return -1;

  int decrypted = lauxus_gcm_decrypt(this->aes_gcm_ctx, buffer+read, cypher_size, aad, aad_size, plain);
  if ((size_t)decrypted != cypher_size)
    return -1;
  read += decrypted;

  if (this->p_load_sensitive(plain_size, plain) != decrypted)
    return -1;
  return read;
}
