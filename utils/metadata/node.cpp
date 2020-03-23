#include "../../utils/metadata/node.hpp"
#include "../../utils/encryption.hpp"
#include <string>
#include <vector>


Node::Node(const std::string &filename) {
  this->filename = filename;
  this->aes_gcm_ctx = new AES_GCM_context();
}

Node::~Node() {
  delete this->aes_gcm_ctx;
}


size_t Node::metadata_size() {
  return AES_GCM_context::size();
}

int Node::dump_metadata(const size_t buffer_size, char *buffer) {
  size_t size_aad = this->size_aad(), gcm_size_aad = this->aes_gcm_ctx->size_aad();
  size_t size_sensitive = this->size_sensitive();
  char aad_buffer[size_aad+gcm_size_aad], sensitive_buffer[size_sensitive];

  if(this->dump_aad(aad_buffer+gcm_size_aad) < 0 ||
      this->aes_gcm_ctx->dump_aad(aad_buffer) < 0 ||
      this->dump_sensitive(sensitive_buffer) < 0)
    return -1;

  size_t encrypted = this->aes_gcm_ctx->encrypt((uint8_t*)sensitive_buffer, size_sensitive,
                    (uint8_t*)aad_buffer, size_aad+gcm_size_aad, (uint8_t*)buffer+this->metadata_size());
  size_t dumped = this->aes_gcm_ctx->dump(buffer);
  if (encrypted < 0 || dumped < 0)
    return -1;

  return encrypted+dumped;
}

int Node::load_metadata(const size_t buffer_size, const char *buffer) {
  size_t gcm_size = this->aes_gcm_ctx->load(buffer);
  size_t size_sensitive = buffer_size - gcm_size;
  size_t size_aad = this->size_aad(), gcm_size_aad = this->aes_gcm_ctx->size_aad();
  char aad_buffer[size_aad+gcm_size_aad], sensitive_buffer[size_sensitive];

  if(this->dump_aad(aad_buffer+gcm_size_aad) < 0 ||
      this->aes_gcm_ctx->dump_aad(aad_buffer) < 0)
    return -1;

  size_t decrypted = this->aes_gcm_ctx->decrypt((uint8_t*)buffer+gcm_size, size_sensitive,
                      (uint8_t*)aad_buffer, size_aad+gcm_size_aad, (uint8_t*)sensitive_buffer);
  size_t loaded = this->load_sensitive(size_sensitive, sensitive_buffer);
  if (decrypted < 0 || loaded < 0)
    return -1;

  return decrypted+loaded;
}
