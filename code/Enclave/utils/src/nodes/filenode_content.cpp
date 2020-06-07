#include "../../headers/nodes/filenode_content.hpp"


FilenodeContent::FilenodeContent(size_t block_size, map<size_t, lauxus_ctr_t*> *aes_ctr_ctxs) {
  this->block_size = block_size;
  this->aes_ctr_ctxs = aes_ctr_ctxs;

  this->plain = new map<size_t, vector<uint8_t>>();
  this->cipher = new map<size_t, vector<uint8_t>>();
}

FilenodeContent::~FilenodeContent() {
  this->plain->clear(); this->cipher->clear();
  delete this->plain;
  delete this->cipher;
}


void FilenodeContent::free_loaded() {
  this->plain->clear(); this->cipher->clear();
}


int FilenodeContent::write(const long offset, const size_t data_size, const uint8_t *data) {
  map<string, size_t> block_required = FilenodeContent::block_required(this->block_size, offset, data_size);
  size_t written = 0, offset_in_block = block_required["offset_in_block"];

  if (data_size == 0 && offset == 0)
    return 0;
  if (offset_in_block > 0 && this->plain->count(block_required["start_block"]) <= 0) // can't write on non existing block with offset
    return -1;

  // fill as much as we can inside available blocks
  size_t index = 0;
  for (index = block_required["start_block"]; index <= block_required["end_block"] && this->plain->count(index) > 0; index++, offset_in_block=0) {
    vector<uint8_t> &block = (*this->plain)[index];

    auto size_to_write = data_size - written;
    if (this->block_size < (offset_in_block + size_to_write)) {
      size_to_write = this->block_size - offset_in_block;
      this->size += this->block_size - block.size();
      block.resize(this->block_size);
    } else {
      this->size += offset_in_block + size_to_write - block.size();
      block.resize(offset_in_block + size_to_write);
    }
    memcpy(&(block)[0]+offset_in_block, data+written, size_to_write);
    written += size_to_write;

    if (this->encrypt_block(index) < 0)
      return -1;
  }

  // Create new blocks from scratch for extra
  for (; written < data_size; index++) {
    size_t bytes_to_write = data_size - written;
    if (this->block_size < bytes_to_write)
      bytes_to_write = this->block_size;

    vector<uint8_t> block = vector<uint8_t>(bytes_to_write);
    memcpy(&(block)[0], data + written, bytes_to_write);

    lauxus_ctr_t *new_ctx = (lauxus_ctr_t*) malloc(sizeof(lauxus_ctr_t)); lauxus_random_ctr(new_ctx);
    this->plain->insert(pair<size_t, vector<uint8_t>>(index, block));
    this->aes_ctr_ctxs->insert(pair<size_t, lauxus_ctr_t*>(index, new_ctx));
    written += bytes_to_write;
    this->size += bytes_to_write;

    if (this->encrypt_block(index) < 0)
      return -1;
  }

  return written;
}

int FilenodeContent::read(const long offset, const size_t buffer_size, uint8_t *buffer) {
  map<string, size_t> block_required = FilenodeContent::block_required(this->block_size, offset, buffer_size);
  size_t read = 0, offset_in_block = block_required["offset_in_block"];

  if (buffer_size == 0 && offset == 0)
    return 0;
  if (this->plain->count(block_required["start_block"]) <= 0)
    return 0;

  for (size_t index = block_required["start_block"]; index <= block_required["end_block"] && read < buffer_size; index++, offset_in_block=0) {
    if (this->plain->count(index) <= 0)
      break;
    vector<uint8_t> &block = (*this->plain)[index];

    auto size_to_copy = buffer_size - read;
    if (size_to_copy > block.size()-offset_in_block)
      size_to_copy = block.size()-offset_in_block;

    memcpy(buffer+read, &(block)[0]+offset_in_block, size_to_copy);
    read += size_to_copy;
  }
  return read;
}


int FilenodeContent::e_size(const long up_offset, const size_t up_size) {
  map<string, size_t> block_required = FilenodeContent::block_required(this->block_size, up_offset, up_size);

  size_t size = (block_required["end_block"]-block_required["start_block"]) * this->block_size;
  size += (*this->cipher)[block_required["end_block"]].size();
  return size;
}

int FilenodeContent::e_dump(const long up_offset, const size_t up_size, const size_t buffer_size, uint8_t *buffer) {
  map<string, size_t> block_required = FilenodeContent::block_required(this->block_size, up_offset, up_size);
  size_t written = 0;

  for (size_t index = block_required["start_block"]; index <= block_required["end_block"]; index++) {
    vector<uint8_t> &block = (*this->cipher)[index];
    memcpy(buffer+written, &(block)[0], block.size());
    written += block.size();
  }

  return block_required["start_block"] * this->block_size; // return the offset on which it should start editing the file
}

int FilenodeContent::e_load(const long up_offset, const size_t up_size, const size_t buffer_size, const uint8_t *buffer) {
  map<string, size_t> block_required = FilenodeContent::block_required(this->block_size, up_offset, up_size);
  size_t read = 0;

  for (size_t index = block_required["start_block"]; index <= block_required["end_block"] && read < buffer_size; index++) {
    size_t size_to_read = buffer_size - read ;
    if (size_to_read > this->block_size)
      size_to_read = this->block_size;

    vector<uint8_t> block = vector<uint8_t>(size_to_read);
    memcpy(&(block)[0], buffer+read, size_to_read);
    read += size_to_read;
    this->cipher->insert(pair<size_t, vector<uint8_t>>(index, block));
    if (this->decrypt_block(index) < 0)
      return -1;
  }

  return read;
}


int FilenodeContent::encrypt_block(const size_t block_index) {
  vector<uint8_t> &plain_block = (*this->plain)[block_index];
  lauxus_ctr_t *ctx = (*this->aes_ctr_ctxs)[block_index];
  sgx_read_rand(ctx->ctr, AES_CTR_COUNTER_SIZE);
  if (this->cipher->count(block_index) > 0) // already exists
    (*this->cipher)[block_index].resize(plain_block.size());
  else
    this->cipher->insert(pair<size_t, vector<uint8_t>>(block_index, vector<uint8_t>(plain_block.size())));

  vector<uint8_t> &cipher_block = (*this->cipher)[block_index];
  return lauxus_ctr_encrypt(ctx, &(plain_block)[0], plain_block.size(), &(cipher_block)[0]);
}

int FilenodeContent::decrypt_block(const size_t block_index) {
  vector<uint8_t> &cipher_block = (*this->cipher)[block_index];
  lauxus_ctr_t *ctx = (*this->aes_ctr_ctxs)[block_index];

  if (block_index < this->plain->size()) // already exists
    (*this->plain)[block_index].resize(cipher_block.size());
  else
    this->plain->insert(pair<size_t, vector<uint8_t>>(block_index, vector<uint8_t>(cipher_block.size())));

  vector<uint8_t> &plain_block = (*this->plain)[block_index];
  return lauxus_ctr_decrypt(ctx, &(cipher_block)[0], cipher_block.size(), &(plain_block)[0]);
}


// Static functions
map<string, size_t> FilenodeContent::block_required(const size_t block_size, const long offset, const size_t length) {
  map<string, size_t> result;
  result["start_block"] = (size_t)(offset/block_size);
  result["end_block"] = (size_t)((offset+length-1)/block_size);
  if (offset+length < 1)
    result["end_block"] = 0;
  result["offset_in_block"] = offset%block_size;
  return result;
}
