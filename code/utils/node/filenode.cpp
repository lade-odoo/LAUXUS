#include "filenode.hpp"
#include "filenode_content.hpp"
#include "supernode.hpp"
#include "node.hpp"
#include "../encryption/aes_gcm.hpp"
#include "../encryption/aes_ctr.hpp"
#include "../users/user.hpp"

#include <string>
#include <cstring>
#include <map>
#include <vector>



Filenode::Filenode(const std::string &uuid, const std::string &relative_path,
        AES_GCM_context *root_key, const size_t block_size):Node::Node(uuid, relative_path, root_key) {

  this->allowed_users = new std::map<int, unsigned char>();
  this->aes_ctr_ctxs = new std::vector<AES_CTR_context*>();
  this->content = new FilenodeContent(block_size, this->aes_ctr_ctxs);
}
Filenode::Filenode(const std::string &uuid, AES_GCM_context *root_key, const size_t block_size):Filenode::Filenode(uuid, "", root_key, block_size) {}

Filenode::~Filenode() {
  for (auto it = this->aes_ctr_ctxs->begin(); it != this->aes_ctr_ctxs->end(); ) {
    delete * it; it = this->aes_ctr_ctxs->erase(it);
  }

  delete this->content;
  delete this->aes_ctr_ctxs; delete this->allowed_users;
}


bool Filenode::equals(Filenode *other) {
  if (this->allowed_users->size() != other->allowed_users->size())
    return false;
  if (this->aes_ctr_ctxs->size() != other->aes_ctr_ctxs->size())
    return false;

  // check allowed_users
  for (auto it = this->allowed_users->begin(); it != this->allowed_users->end(); ++it)
    if (other->allowed_users->find(it->first) == other->allowed_users->end())
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

bool Filenode::is_user_allowed(const unsigned char required_policy, User *user) {
  if (user->is_root())
    return true;

  auto it = this->allowed_users->find(user->id);
  if (it == this->allowed_users->end())
    return false;

  unsigned char policy = it->second;
  return required_policy == (required_policy & policy);
}

int Filenode::edit_user_policy(const unsigned char policy, User *user) {
  if (user->is_root())
    return -1;

  unsigned char effective_policy = policy;
  if (policy == Filenode::OWNER_POLICY)
    effective_policy = Filenode::OWNER_POLICY | Filenode::READ_POLICY | Filenode::WRITE_POLICY | Filenode::EXEC_POLICY;

  auto it = this->allowed_users->find(user->id);
  if (it == this->allowed_users->end() && policy != 0) {
    this->allowed_users->insert(std::pair<int, unsigned char>(user->id, effective_policy));
    return 0;
  }

  if (policy == 0)
    this->allowed_users->erase(it);
  else
    it->second = policy;
  return 0;
}

int Filenode::getattr(User *user) {
  if (user->is_root())
    return READ_POLICY | WRITE_POLICY | EXEC_POLICY;

  auto it = this->allowed_users->find(user->id);
  if (it == this->allowed_users->end())
    return 0;

  if (it->second >= Filenode::OWNER_POLICY)
    return it->second-Filenode::OWNER_POLICY;
  return it->second;
}


size_t Filenode::p_sensitive_size() {
  size_t size = Node::p_sensitive_size();
  size += sizeof(int) + this->allowed_users->size() * (sizeof(int) + sizeof(unsigned char));
  size += sizeof(int) + this->aes_ctr_ctxs->size() * AES_CTR_context::size();
  return size;
}

int Filenode::p_dump_sensitive(const size_t buffer_size, char *buffer) {
  if (buffer_size < this->p_sensitive_size())
    return -1;

  int written = Node::p_dump_sensitive(buffer_size, buffer);
  if (written < 0)
    return -1;

  int users_len = this->allowed_users->size();
  std::memcpy(buffer+written, &users_len, sizeof(int)); written += sizeof(int);
  for (auto it = this->allowed_users->begin(); it != this->allowed_users->end(); ++it) {
    int user_id = it->first;
    unsigned char policy = it->second;

    std::memcpy(buffer+written, &user_id, sizeof(int)); written += sizeof(int);
    std::memcpy(buffer+written, &policy, sizeof(unsigned char)); written += sizeof(unsigned char);
  }

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

  int users_len = 0;
  std::memcpy(&users_len, buffer+read, sizeof(int)); read += sizeof(int);
  for (int i = 0; i < users_len; i++) {
    int user_id = 0; unsigned char policy = 0;

    std::memcpy(&user_id, buffer+read, sizeof(int)); read += sizeof(int);
    std::memcpy(&policy, buffer+read, sizeof(unsigned char)); read += sizeof(unsigned char);

    this->allowed_users->insert(std::pair<int, unsigned char>(user_id, policy));
  }

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
