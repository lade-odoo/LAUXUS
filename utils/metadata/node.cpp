#include "../../utils/metadata/node.hpp"
#include "../../utils/encryption.hpp"
#include <string>
#include <vector>


Node::Node(const std::string &path, AES_GCM_context *root_key) {
  this->path = path;
  this->root_key = root_key;
  this->aes_gcm_ctx = new AES_GCM_context();
}

Node::~Node() {
  delete this->aes_gcm_ctx;
}


size_t Node::metadata_size() {
  return this->preamble_size() + AES_GCM_context::size() + this->size_sensitive();
}

int Node::dump_metadata(const size_t buffer_size, char *buffer) {
  size_t size_preamble = this->preamble_size(), size_aad_crypto_context = this->aes_gcm_ctx->size_aad();
  size_t size_sensitive = this->size_sensitive();
  char aad_buffer[size_preamble+size_aad_crypto_context], sensitive_buffer[size_sensitive];

  if(this->dump_preamble(aad_buffer) < 0 ||
      this->aes_gcm_ctx->dump_aad(aad_buffer+size_preamble) < 0 ||
      this->dump_sensitive(size_sensitive, sensitive_buffer) < 0)
    return -1;

  int encrypted = this->aes_gcm_ctx->encrypt((uint8_t*)sensitive_buffer, size_sensitive,
                    (uint8_t*)aad_buffer, size_preamble+size_aad_crypto_context, (uint8_t*)buffer+(buffer_size-size_sensitive));
  std::memcpy(aad_buffer, buffer, size_preamble);
  int ctx_dumped = this->aes_gcm_ctx->encrypt_key_and_dump(this->root_key, buffer+size_preamble);
  if (encrypted < 0 || ctx_dumped < 0)
    return -1;

  return size_preamble+ctx_dumped+encrypted;
}

int Node::load_metadata(const size_t buffer_size, const char *buffer) {
  size_t size_preamble = this->load_preamble(buffer_size, buffer);
  size_t gcm_size = this->aes_gcm_ctx->decrypt_key_and_load(this->root_key, buffer+size_preamble);
  size_t size_sensitive = buffer_size-size_preamble-gcm_size;
  size_t size_aad_crypto_context = this->aes_gcm_ctx->size_aad();
  char aad_buffer[size_preamble+size_aad_crypto_context], sensitive_buffer[size_sensitive];

  if(this->dump_preamble(aad_buffer) < 0 ||
      this->aes_gcm_ctx->dump_aad(aad_buffer+size_preamble) < 0)
    return -1;

  size_t decrypted = this->aes_gcm_ctx->decrypt((uint8_t*)buffer+size_preamble+gcm_size, size_sensitive,
                      (uint8_t*)aad_buffer, size_preamble+size_aad_crypto_context, (uint8_t*)sensitive_buffer);
  size_t loaded = this->load_sensitive(size_sensitive, sensitive_buffer);
  if (decrypted < 0 || loaded < 0)
    return -1;

  return decrypted+loaded;
}


size_t Node::preamble_size() {
  return 0/*length int + size filename*/;
}

int Node::dump_preamble(char *buffer) {
  return 0/*dump length filename + dump filename*/;
}

int Node::load_preamble(size_t buffer_size, const char *buffer) {
  return 0;
}
