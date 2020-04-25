#include "filenode_content.hpp"
#include "../encryption/aes_ctr.hpp"

#include <string>
#include <cstring>
#include <vector>
#include <map>

using namespace std;



FilenodeContent::FilenodeContent(size_t block_size, map<size_t, AES_CTR_context*> *aes_ctr_ctxs) {
  this->block_size = block_size;
  this->aes_ctr_ctxs = aes_ctr_ctxs;

  this->plain = new map<size_t, vector<char>*>();
  this->cipher = new map<size_t, vector<char>*>();
}

FilenodeContent::~FilenodeContent() {
  for (auto it = this->plain->begin(); it != this->plain->end(); ++it) {
    vector<char> *block = it->second;
    delete block;
  }

  for (auto it = this->cipher->begin(); it != this->cipher->end(); ++it) {
    vector<char> *block = it->second;
    delete block;
  }

  delete this->plain; delete this->cipher;
}


int FilenodeContent::write(const long offset, const size_t data_size, const char *data) {
  map<string, size_t> block_required = FilenodeContent::block_required(this->block_size, offset, data_size);
  size_t written = 0, offset_in_block = block_required["offset_in_block"];

  if (data_size == 0 && offset == 0)
    return 0;
  if (offset_in_block > 0 && this->plain->count(block_required["start_block"]) <= 0) // can't write on non existing block with offset
    return -1;

  // fill as much as we can inside available blocks
  size_t index = 0;
  for (index = block_required["start_block"]; index <= block_required["end_block"] && this->plain->count(index) > 0; index++, offset_in_block=0) {
    vector<char> *block = (*this->plain)[index];

    auto size_to_write = data_size - written;
    if (this->block_size < (offset_in_block + size_to_write)) {
      size_to_write = this->block_size - offset_in_block;
      this->size += this->block_size - block->size();
      block->resize(this->block_size);
    } else {
      this->size += offset_in_block + size_to_write - block->size();
      block->resize(offset_in_block + size_to_write);
    }
    memcpy(&(*block)[0]+offset_in_block, data+written, size_to_write);
    written += size_to_write;

    if (this->encrypt_block(index) < 0)
      return -1;
  }

  // Create new blocks from scratch for extra
  for (; written < data_size; index++) {
    size_t bytes_to_write = data_size - written;
    if (this->block_size < bytes_to_write)
      bytes_to_write = this->block_size;

    vector<char> *block = new vector<char>(bytes_to_write);
    memcpy(&(*block)[0], data + written, bytes_to_write);

    this->plain->insert(pair<size_t, vector<char>*>(index, block));
    this->aes_ctr_ctxs->insert(pair<size_t, AES_CTR_context*>(index, new AES_CTR_context()));
    written += bytes_to_write;
    this->size += bytes_to_write;

    if (this->encrypt_block(index) < 0)
      return -1;
  }

  return written;
}

int FilenodeContent::read(const long offset, const size_t buffer_size, char *buffer) {
  map<string, size_t> block_required = FilenodeContent::block_required(this->block_size, offset, buffer_size);
  size_t read = 0, offset_in_block = block_required["offset_in_block"];

  if (buffer_size == 0 && offset == 0)
    return 0;
  if (this->plain->count(block_required["start_block"]) <= 0)
    return 0;

  for (size_t index = block_required["start_block"]; index <= block_required["end_block"] && read < buffer_size; index++, offset_in_block=0) {
    if (this->plain->count(index) <= 0)
      break;
    vector<char> *block = (*this->plain)[index];

    auto size_to_copy = buffer_size - read;
    if (size_to_copy > block->size()-offset_in_block)
      size_to_copy = block->size()-offset_in_block;

    memcpy(buffer+read, &(*block)[0]+offset_in_block, size_to_copy);
    read += size_to_copy;
  }
  return read;
}


int FilenodeContent::e_size(const long up_offset, const size_t up_size) {
  map<string, size_t> block_required = FilenodeContent::block_required(this->block_size, up_offset, up_size);

  size_t size = (block_required["end_block"]-block_required["start_block"]) * this->block_size;
  size += (*this->cipher)[block_required["end_block"]]->size();
  return size;
}

int FilenodeContent::e_dump(const long up_offset, const size_t up_size, const size_t buffer_size, char *buffer) {
  map<string, size_t> block_required = FilenodeContent::block_required(this->block_size, up_offset, up_size);
  size_t written = 0;

  for (size_t index = block_required["start_block"]; index <= block_required["end_block"]; index++) {
    vector<char> *block = (*this->cipher)[index];
    memcpy(buffer+written, &(*block)[0], block->size());
    written += block->size();
  }

  return block_required["start_block"] * this->block_size; // return the offset on which it should start editing the file
}

int FilenodeContent::e_load(const long up_offset, const size_t up_size, const size_t buffer_size, const char *buffer) {
  map<string, size_t> block_required = FilenodeContent::block_required(this->block_size, up_offset, up_size);
  size_t read = 0;

  for (size_t index = block_required["start_block"]; index <= block_required["end_block"] && read < buffer_size; index++) {
    size_t size_to_read = buffer_size - read ;
    if (size_to_read > this->block_size)
      size_to_read = this->block_size;

    vector<char> *block = new vector<char>(size_to_read);
    memcpy(&(*block)[0], buffer+read, size_to_read);
    read += size_to_read;
    this->cipher->insert(pair<size_t, vector<char>*>(index, block));
    if (this->decrypt_block(index) < 0)
      return -1;
  }

  return read;
}


int FilenodeContent::encrypt_block(const size_t block_index) {
  vector<char> *plain_block = (*this->plain)[block_index];
  AES_CTR_context *ctx = (*this->aes_ctr_ctxs)[block_index];
  if (this->cipher->count(block_index) > 0) // already exists
    (*this->cipher)[block_index]->resize(plain_block->size());
  else
    this->cipher->insert(pair<size_t, vector<char>*>(block_index, new vector<char>(plain_block->size())));

  vector<char> *cipher_block = (*this->cipher)[block_index];
  return ctx->encrypt((uint8_t*)&(*plain_block)[0], plain_block->size(), (uint8_t*)&(*cipher_block)[0]);
}

int FilenodeContent::decrypt_block(const size_t block_index) {
  vector<char> *cipher_block = (*this->cipher)[block_index];
  AES_CTR_context *ctx = (*this->aes_ctr_ctxs)[block_index];

  if (block_index < this->plain->size()) // already exists
    (*this->plain)[block_index]->resize(cipher_block->size());
  else
    this->plain->insert(pair<size_t, vector<char>*>(block_index, new vector<char>(cipher_block->size())));

  vector<char> *plain_block = (*this->plain)[block_index];
  return ctx->decrypt((uint8_t*)&(*cipher_block)[0], cipher_block->size(), (uint8_t*)&(*plain_block)[0]);
}


// Static functions
map<string, size_t> FilenodeContent::block_required(const size_t block_size, const long offset, const size_t length) {
  map<string, size_t> result;
  result["start_block"] = (int)(offset/block_size);
  result["end_block"] = (int)((offset+length-1)/block_size);
  result["offset_in_block"] = offset%block_size;
  return result;
}
