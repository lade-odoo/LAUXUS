#include "filenode.hpp"
#include "filenode_content.hpp"
#include "supernode.hpp"
#include "node.hpp"
#include "../encryption/aes_gcm.hpp"
#include "../encryption/aes_ctr.hpp"

#include <string>
#include <cstring>
#include <map>
#include <vector>



Filenode::Filenode(const std::string &uuid, const std::string &relative_path,
        AES_GCM_context *root_key, const size_t block_size):Node::Node(uuid, relative_path, root_key) {

  this->node_type = Node::FILENODE_TYPE;
  this->aes_ctr_ctxs = new std::vector<AES_CTR_context*>();
  this->content = new FilenodeContent(block_size, this->aes_ctr_ctxs);

  this->add_node_entry(this); // ls of a file returns the file
}
Filenode::Filenode(const std::string &uuid, AES_GCM_context *root_key, const size_t block_size):Filenode::Filenode(uuid, "", root_key, block_size) {}

Filenode::~Filenode() {
  this->remove_node_entry(this);
  for (auto it = this->aes_ctr_ctxs->begin(); it != this->aes_ctr_ctxs->end(); ) {
    delete * it; it = this->aes_ctr_ctxs->erase(it);
  }

  delete this->content;
  delete this->aes_ctr_ctxs;
}


bool Filenode::equals(Filenode *other) {
  if (this->aes_ctr_ctxs->size() != other->aes_ctr_ctxs->size())
    return false;

  // check aes_ctr_ctxs
  for (size_t i = 0; i < this->aes_ctr_ctxs->size(); i++) {
    auto it = this->aes_ctr_ctxs->at(i);
    auto it2 = other->aes_ctr_ctxs->at(i);
    if (!it->equals(it2))
      return false;
  }

  return Node::equals(other);
}


bool Filenode::is_correct_node(string parent_path) {
  return parent_path.compare(this->relative_path) == 0;
}

Node* Filenode::retrieve_node(string relative_path) {
  return this;
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
    AES_CTR_context *context = *it;
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

    this->aes_ctr_ctxs->push_back(context);
  }

  return read;
}


size_t Filenode::file_size() {
  return this->content->size();
}
int Filenode::write(const long offset, const size_t data_size, const char *data) {
  return this->content->write(offset, data_size, data);
}
int Filenode::read(const long offset, const size_t buffer_size, char *buffer) {
  return this->content->read(offset, buffer_size, buffer);
}


int Filenode::e_content_size(const long up_offset, const size_t up_size) {
  return this->content->e_size(up_offset, up_size);
}
int Filenode::e_dump_content(const long up_offset, const size_t up_size, const size_t buffer_size, char *buffer) {
  return this->content->e_dump(up_offset, up_size, buffer_size, buffer);
}
int Filenode::e_load_content(const long offset, const size_t buffer_size, const char *buffer) {
  return this->content->e_load(offset, buffer_size, buffer);
}
