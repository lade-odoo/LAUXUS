#include "../../utils/metadata/filenode.hpp"
#include "../../utils/metadata/supernode.hpp"
#include "../../utils/metadata/node.hpp"
#include "../../utils/encryption.hpp"
#include "../../utils/users/user.hpp"

#include <string>
#include <cstring>
#include <map>
#include <vector>



Filenode::Filenode(const std::string &filename, AES_GCM_context *root_key,
                    const size_t block_size):Node::Node(filename, root_key) {
  this->block_size = block_size;
  this->allowed_users = new std::map<int, unsigned char>();

  this->plain = new std::vector<std::vector<char>*>();
  this->cipher = new std::vector<std::vector<char>*>();
  this->aes_ctr_ctxs = new std::vector<AES_CTR_context*>();
}

Filenode::~Filenode() {
  for (auto it = this->plain->begin(); it != this->plain->end(); ) {
    delete * it; it = this->plain->erase(it);
  }

  for (auto it = this->cipher->begin(); it != this->cipher->end(); ) {
    delete * it; it = this->cipher->erase(it);
  }

  for (auto it = this->aes_ctr_ctxs->begin(); it != this->aes_ctr_ctxs->end(); ) {
    delete * it; it = this->aes_ctr_ctxs->erase(it);
  }

  delete this->plain; delete this->cipher;
  delete this->aes_ctr_ctxs; delete this->allowed_users;
}


bool Filenode::equals(Filenode *other) {
  if (this->allowed_users->size() != other->allowed_users->size())
    return false;
  if (this->aes_ctr_ctxs->size() != other->aes_ctr_ctxs->size())
    return false;
  if (this->plain->size() != other->plain->size())
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

  // check plain
  for (size_t i = 0; i < this->plain->size(); i++) {
    std::vector<char> *it = this->plain->at(i);
    std::vector<char> *it2 = other->plain->at(i);
    if (it->size() != it2->size())
      return false;
    for (size_t j = 0; j < it->size(); j++) {
      char c1 = it->at(j);
      char c2 = it2->at(j);
      if (c1 != c2)
        return false;
    }
  }

  return Node::equals(other);
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


size_t Filenode::file_size() {
  if (this->plain->empty())
    return 0;

  size_t size = (this->plain->size() - 1) * this->block_size;
  size += this->plain->back()->size();
  return size;
}

int Filenode::getattr(User *user) {
  if (user->is_root())
    return READ_POLICY | WRITE_POLICY | EXEC_POLICY;

  auto it = this->allowed_users->find(user->id);
  if (it == this->allowed_users->end())
    return 0;

  return it->second;
}

int Filenode::write(const long offset, const size_t data_size, const char *data) {
  size_t written = 0;
  size_t offset_in_block = offset % block_size;
  size_t block_index = (size_t)((offset-offset_in_block)/this->block_size);

  // fill as much as we can inside available blocks
  if (block_index < this->plain->size()) {
    std::vector<char> *block = this->plain->at(block_index);
    size_t bytes_to_write = data_size;
    if (this->block_size < (offset_in_block + data_size)) {
      bytes_to_write = this->block_size - offset_in_block;
      block->resize(this->block_size);
    } else {
      block->resize(offset_in_block + data_size);
    }
    std::memcpy(&(*block)[0] + offset_in_block, data, bytes_to_write);
    written += bytes_to_write;

    if (Filenode::encrypt_block(block_index) < 0)
      return -1;
  }

  // Create new blocks from scratch for extra
  while (written < data_size) {
    size_t bytes_to_write = data_size - written;
    if (this->block_size < bytes_to_write) {
      bytes_to_write = this->block_size;
    }
    std::vector<char> *block = new std::vector<char>(bytes_to_write);
    std::memcpy(&(*block)[0], data + written, bytes_to_write);
    this->plain->push_back(block);
    this->aes_ctr_ctxs->push_back(new AES_CTR_context());
    written += bytes_to_write;

    if (Filenode::encrypt_block(this->plain->size()-1) < 0)
      return -1;
  }

  return written;
}

int Filenode::read(const long offset, const size_t buffer_size, char *buffer) {
  size_t read = 0;
  size_t offset_in_block = offset % this->block_size;
  size_t block_index = (size_t)((offset-offset_in_block)/this->block_size);

  if (this->plain->size() <= block_index)
    return 0;

  for (size_t index = block_index;
       index < this->plain->size() && read < buffer_size;
       index++, offset_in_block = 0) {
    std::vector<char> *block = this->plain->at(index);
    auto size_to_copy = buffer_size - read;
    if (size_to_copy > block->size()) {
      size_to_copy = block->size();
    }
    std::memcpy(buffer + read, &(*block)[0] + offset_in_block, size_to_copy);
    read += size_to_copy;
  }

  return (int)read;
}


size_t Filenode::p_sensitive_size() {
  size_t size = 2 * sizeof(int);
  size += this->allowed_users->size() * (sizeof(int) + sizeof(unsigned char));
  return size + this->aes_ctr_ctxs->size() * AES_CTR_context::size();
}

int Filenode::p_dump_sensitive(const size_t buffer_size, char *buffer) {
  size_t written = 0;

  int users_len = this->allowed_users->size();
  std::memcpy(buffer, &users_len, sizeof(int)); written += sizeof(int);
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
  size_t read = 0;

  int users_len = 0;
  std::memcpy(&users_len, buffer, sizeof(int)); read += sizeof(int);
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


int Filenode::e_content_size(const long up_offset, const size_t up_size) {
  size_t written = 0;
  size_t offset_in_block = up_offset % this->block_size;
  size_t start_index = (size_t)((up_offset-offset_in_block)/this->block_size);
  offset_in_block = (up_offset+up_size) % this->block_size;
  size_t end_index = (size_t)((up_offset+up_size-offset_in_block)/this->block_size);

  if (offset_in_block > 0)
    return (end_index-start_index) * this->block_size + this->cipher->at(end_index)->size();
  return (end_index-start_index) * this->block_size;
}

int Filenode::e_dump_content(const long up_offset, const size_t up_size, const size_t buffer_size, char *buffer) {
  size_t written = 0;
  size_t offset_in_block = up_offset % this->block_size;
  size_t start_index = (size_t)((up_offset-offset_in_block)/this->block_size);

  if (this->cipher->size() <= start_index)
    return -1;

  std::vector<char> *block = this->cipher->at(start_index);
  for (size_t index = start_index; written+block->size() <= buffer_size; index++) {
    std::memcpy(buffer + written, &(*block)[0], block->size());
    written += block->size();
    if (this->cipher->size() <= index+1)
      break;
    block = this->cipher->at(index+1);
  }

  return start_index * this->block_size; // return the offset on which it should start editing the file
}

int Filenode::e_load_content(const long offset, const size_t buffer_size, const char *buffer) {
  size_t start_index = (size_t)(offset/this->block_size);
  size_t size_decrypted = 0;

  for (int block_index = start_index; size_decrypted != buffer_size; block_index++) {
    size_t size = this->block_size;
    if (buffer_size-size_decrypted < size)
      size = buffer_size;

    std::vector<char> *block = new std::vector<char>(size);
    std::memcpy(&(*block)[0], buffer, size);
    this->cipher->push_back(block);
    size_decrypted += Filenode::decrypt_block(block_index);
  }

  return size_decrypted;
}

int Filenode::encrypt_block(const size_t block_index) {
  std::vector<char> *plain_block = this->plain->at(block_index);
  AES_CTR_context *ctx = this->aes_ctr_ctxs->at(block_index);
  if (block_index < this->cipher->size()) // already exists
    this->cipher->at(block_index)->resize(plain_block->size());
  else
    this->cipher->push_back(new std::vector<char>(plain_block->size()));

  std::vector<char> *cipher_block = this->cipher->at(block_index);
  return ctx->encrypt((uint8_t*)&(*plain_block)[0], plain_block->size(), (uint8_t*)&(*cipher_block)[0]);
}

int Filenode::decrypt_block(const size_t block_index) {
  std::vector<char> *cipher_block = this->cipher->at(block_index);
  AES_CTR_context *ctx = this->aes_ctr_ctxs->at(block_index);

  if (block_index < this->plain->size()) // already exists
    this->plain->at(block_index)->resize(cipher_block->size());
  else
    this->plain->push_back(new std::vector<char>(cipher_block->size()));

  std::vector<char> *plain_block = this->plain->at(block_index);
  return ctx->decrypt((uint8_t*)&(*cipher_block)[0], cipher_block->size(), (uint8_t*)&(*plain_block)[0]);
}
