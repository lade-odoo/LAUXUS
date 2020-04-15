#include "../../utils/metadata/filenode_content.hpp"
#include "../../utils/encryption/aes_ctr.hpp"

#include <string>
#include <cstring>
#include <vector>



FilenodeContent::FilenodeContent(size_t block_size, std::vector<AES_CTR_context*> *aes_ctr_ctxs) {
  this->block_size = block_size;
  this->aes_ctr_ctxs = aes_ctr_ctxs;

  this->plain = new std::vector<std::vector<char>*>();
  this->cipher = new std::vector<std::vector<char>*>();
}

FilenodeContent::~FilenodeContent() {
  for (auto it = this->plain->begin(); it != this->plain->end(); ) {
    delete * it; it = this->plain->erase(it);
  }

  for (auto it = this->cipher->begin(); it != this->cipher->end(); ) {
    delete * it; it = this->cipher->erase(it);
  }

  delete this->plain; delete this->cipher;
}


bool FilenodeContent::equals(FilenodeContent *other) {
  if (this->plain->size() != other->plain->size())
    return false;

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

  return true;
}


size_t FilenodeContent::size() {
  if (this->plain->empty())
    return 0;

  size_t size = (this->plain->size() - 1) * this->block_size;
  size += this->plain->back()->size();
  return size;
}

int FilenodeContent::write(const long offset, const size_t data_size, const char *data) {
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

    if (this->encrypt_block(block_index) < 0)
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

    if (this->encrypt_block(this->plain->size()-1) < 0)
      return -1;
  }

  return written;
}

int FilenodeContent::read(const long offset, const size_t buffer_size, char *buffer) {
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


int FilenodeContent::e_size(const long up_offset, const size_t up_size) {
  size_t written = 0;
  size_t offset_in_block = up_offset % this->block_size;
  size_t start_index = (size_t)((up_offset-offset_in_block)/this->block_size);
  offset_in_block = (up_offset+up_size) % this->block_size;
  size_t end_index = (size_t)((up_offset+up_size-offset_in_block)/this->block_size);

  if (offset_in_block > 0)
    return (end_index-start_index) * this->block_size + this->cipher->at(end_index)->size();
  return (end_index-start_index) * this->block_size;
}

int FilenodeContent::e_dump(const long up_offset, const size_t up_size, const size_t buffer_size, char *buffer) {
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

int FilenodeContent::e_load(const long offset, const size_t buffer_size, const char *buffer) {
  size_t start_index = (size_t)(offset/this->block_size);
  size_t size_decrypted = 0;

  for (int block_index = start_index; size_decrypted != buffer_size; block_index++) {
    size_t size = this->block_size;
    if (buffer_size-size_decrypted < size)
      size = buffer_size;

    std::vector<char> *block = new std::vector<char>(size);
    std::memcpy(&(*block)[0], buffer, size);
    this->cipher->push_back(block);
    size_decrypted += this->decrypt_block(block_index);
  }

  return size_decrypted;
}


int FilenodeContent::encrypt_block(const size_t block_index) {
  std::vector<char> *plain_block = this->plain->at(block_index);
  AES_CTR_context *ctx = this->aes_ctr_ctxs->at(block_index);
  if (block_index < this->cipher->size()) // already exists
    this->cipher->at(block_index)->resize(plain_block->size());
  else
    this->cipher->push_back(new std::vector<char>(plain_block->size()));

  std::vector<char> *cipher_block = this->cipher->at(block_index);
  return ctx->encrypt((uint8_t*)&(*plain_block)[0], plain_block->size(), (uint8_t*)&(*cipher_block)[0]);
}

int FilenodeContent::decrypt_block(const size_t block_index) {
  std::vector<char> *cipher_block = this->cipher->at(block_index);
  AES_CTR_context *ctx = this->aes_ctr_ctxs->at(block_index);

  if (block_index < this->plain->size()) // already exists
    this->plain->at(block_index)->resize(cipher_block->size());
  else
    this->plain->push_back(new std::vector<char>(cipher_block->size()));

  std::vector<char> *plain_block = this->plain->at(block_index);
  return ctx->decrypt((uint8_t*)&(*cipher_block)[0], cipher_block->size(), (uint8_t*)&(*plain_block)[0]);
}
