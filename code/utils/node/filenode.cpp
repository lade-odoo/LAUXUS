#include "filenode.hpp"
#include "filenode_content.hpp"
#include "supernode.hpp"
#include "node.hpp"
#include "../encryption/aes_gcm.hpp"
#include "../encryption/aes_ctr.hpp"

#include <string>
#include <cstring>
#include <map>



Filenode::Filenode(const std::string &uuid, const std::string &relative_path,
        AES_GCM_context *root_key, const size_t block_size):Node::Node(uuid, relative_path, root_key) {

  this->node_type = Node::FILENODE_TYPE;
  this->aes_ctr_ctxs = new std::map<size_t, AES_CTR_context*>();
  this->content = new FilenodeContent(block_size, this->aes_ctr_ctxs);

  this->add_node_entry(relative_path, uuid); // ls of a file returns the file
}
Filenode::Filenode(const std::string &uuid, AES_GCM_context *root_key, const size_t block_size):Filenode::Filenode(uuid, "", root_key, block_size) {}

Filenode::~Filenode() {
  for (auto it = this->aes_ctr_ctxs->begin(); it != this->aes_ctr_ctxs->end(); ++it) {
    AES_CTR_context *ctx = it->second;
    delete ctx;
  }

  delete this->content;
  delete this->aes_ctr_ctxs;
}


bool Filenode::equals(Filenode *other) {
  if (this->aes_ctr_ctxs->size() != other->aes_ctr_ctxs->size())
    return false;

  // check aes_ctr_ctxs
  for (auto it = this->aes_ctr_ctxs->begin(); it != this->aes_ctr_ctxs->end(); ++it) {
    if (other->aes_ctr_ctxs->find(it->first) == other->aes_ctr_ctxs->end())
      return false;
    if (!other->aes_ctr_ctxs->find(it->first)->second->equals(it->second))
      return false;
  }

  return Node::equals(other);
}


size_t Filenode::p_preamble_size() {
  size_t size = Node::p_preamble_size();
  return size + sizeof(int);
}

int Filenode::p_dump_preamble(const size_t buffer_size, char *buffer) {
  if (buffer_size < this->p_preamble_size())
    return -1;

  int written = Node::p_dump_preamble(buffer_size, buffer);
  if (written < 0)
    return -1;

  int file_size = this->content->size;
  std::memcpy(buffer+written, &file_size, sizeof(int));
  return written + sizeof(int);
}

int Filenode::p_load_preamble(const size_t buffer_size, const char *buffer) {
  int read = Node::p_load_preamble(buffer_size, buffer);
  if (read < 0)
    return -1;

  int file_size = 0;
  std::memcpy(&file_size, buffer+read, sizeof(int));
  this->content->size = file_size;
  return read + sizeof(int);
}


size_t Filenode::p_sensitive_size() {
  size_t size = Node::p_sensitive_size();
  size += sizeof(int) + this->aes_ctr_ctxs->size() * AES_CTR_context::size();
  return size;
}

int Filenode::p_dump_sensitive(const size_t buffer_size, char *buffer) {
  if (buffer_size < this->p_sensitive_size())
    return -1;

  int written = Node::p_dump_sensitive(buffer_size, buffer);
  if (written < 0)
    return -1;

  int keys_len = this->aes_ctr_ctxs->size();
  std::memcpy(buffer+written, &keys_len, sizeof(int)); written += sizeof(int);
  for (auto it = this->aes_ctr_ctxs->begin(); it != this->aes_ctr_ctxs->end(); ++it) {
    AES_CTR_context *context = it->second;
    int step = context->dump(buffer_size-written, buffer+written);
    if (step < 0)
      return -1;
    written += step;
  }
  return written;
}

int Filenode::p_load_sensitive(const size_t buffer_size, const char *buffer) {
  int read = Node::p_load_sensitive(buffer_size, buffer);
  if (read < 0)
    return -1;

  int keys_len = 0;
  std::memcpy(&keys_len, buffer+read, sizeof(int)); read += sizeof(int);
  for (int i = 0; i < keys_len; i++) {
    AES_CTR_context *context = new AES_CTR_context();

    int step = context->load(buffer_size-read, buffer+read);
    if (step < 0)
      return -1;
    read += step;

    this->aes_ctr_ctxs->insert(std::pair<size_t, AES_CTR_context*>(i, context));
  }

  return read;
}
