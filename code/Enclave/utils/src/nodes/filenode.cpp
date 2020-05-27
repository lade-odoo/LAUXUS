#include "../../headers/nodes/filenode.hpp"


Filenode::Filenode(const string &relative_path, lauxus_gcm_t *root_key, const size_t block_size):Node::Node(relative_path, root_key) {
  this->type = LAUXUS_FILENODE;
  this->aes_ctr_ctxs = new map<size_t, lauxus_ctr_t*>();
  this->content = new FilenodeContent(block_size, this->aes_ctr_ctxs);
}
Filenode::Filenode(lauxus_gcm_t *root_key, const size_t block_size):Filenode::Filenode("", root_key, block_size) {}

Filenode::~Filenode() {
  for (auto it = this->aes_ctr_ctxs->begin(); it != this->aes_ctr_ctxs->end(); ++it)
    free(it->second);

  delete this->content;
  delete this->aes_ctr_ctxs;
}


bool Filenode::equals(Filenode *other) {
  if (this->aes_ctr_ctxs->size() != other->aes_ctr_ctxs->size())
    return false;

  for (auto it = this->aes_ctr_ctxs->begin(); it != this->aes_ctr_ctxs->end(); ++it) {
    size_t index = it->first; lauxus_ctr_t *ctx = it->second;
    if (other->aes_ctr_ctxs->find(index) == other->aes_ctr_ctxs->end() ||
        memcmp(ctx, other->aes_ctr_ctxs->find(index)->second, sizeof(lauxus_ctr_t)) != 0)
      return false;
  }

  return Node::equals(other);
}


size_t Filenode::p_preamble_size() {
  return Node::p_preamble_size() + sizeof(size_t);
}

int Filenode::p_dump_preamble(const size_t buffer_size, uint8_t *buffer) {
  if (buffer_size < this->p_preamble_size())
    return -1;

  int written = Node::p_dump_preamble(buffer_size, buffer);
  if (written < 0)
    return -1;

  size_t file_size = this->content->size;
  memcpy(buffer+written, &file_size, sizeof(size_t)); written += sizeof(size_t);
  return written;
}

int Filenode::p_load_preamble(const size_t buffer_size, const uint8_t *buffer) {
  int read = Node::p_load_preamble(buffer_size, buffer);
  if (read < 0)
    return -1;

  size_t file_size = 0;
  memcpy(&file_size, buffer+read, sizeof(size_t)); read += sizeof(size_t);
  this->content->size = file_size;
  return read;
}


size_t Filenode::p_sensitive_size() {
  size_t size = Node::p_sensitive_size();
  size += sizeof(size_t) + this->aes_ctr_ctxs->size() * sizeof(lauxus_ctr_t);
  return size;
}

int Filenode::p_dump_sensitive(const size_t buffer_size, uint8_t *buffer) {
  if (buffer_size < this->p_sensitive_size())
    return -1;

  int written = Node::p_dump_sensitive(buffer_size, buffer);
  if (written < 0)
    return -1;

  size_t keys_len = this->aes_ctr_ctxs->size();
  memcpy(buffer+written, &keys_len, sizeof(size_t)); written += sizeof(size_t);
  for (auto it = this->aes_ctr_ctxs->begin(); it != this->aes_ctr_ctxs->end(); ++it) {
    lauxus_ctr_t *context = it->second;
    memcpy(buffer+written, context, sizeof(lauxus_ctr_t));
    written += sizeof(lauxus_ctr_t);
  }
  return written;
}

int Filenode::p_load_sensitive(const size_t buffer_size, const uint8_t *buffer) {
  int read = Node::p_load_sensitive(buffer_size, buffer);
  if (read < 0)
    return -1;

  size_t keys_len = 0;
  memcpy(&keys_len, buffer+read, sizeof(size_t)); read += sizeof(size_t);
  for (int i = 0; i < keys_len; i++) {
    lauxus_ctr_t *context = (lauxus_ctr_t*) malloc(sizeof(lauxus_ctr_t));
    memcpy(context, buffer+read, sizeof(lauxus_ctr_t));
    read += sizeof(lauxus_ctr_t);

    this->aes_ctr_ctxs->insert(pair<size_t, lauxus_ctr_t*>(i, context));
  }

  return read;
}
