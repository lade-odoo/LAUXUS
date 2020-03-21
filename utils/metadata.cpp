#include "../utils/metadata.hpp"

#include <cerrno>
#include <string>
#include <cstring>
#include <vector>



///////////////////////////////////////////////////////////////////////////////
////////////////////////////    Filenode     //////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
AES_CTR_context::AES_CTR_context() {
  this->p_key = (sgx_aes_ctr_128bit_key_t*) malloc(16);
  this->p_ctr = (uint8_t*) malloc(16);

  uint8_t key[] = {0x00, 0x01, 0x02, 0x03,
                  0x04, 0x05, 0x06, 0x07,
                  0x08, 0x09, 0x0a, 0x0b,
                  0x0c, 0x0d, 0x0e, 0x0f};
  uint8_t ctr0[] = {0xff, 0xee, 0xdd, 0xcc,
                  0xbb, 0xaa, 0x99, 0x88,
                  0x77, 0x66, 0x55, 0x44,
                  0x33, 0x22, 0x11, 0x00};
  std::memcpy(this->p_key, key, 16);
  std::memcpy(this->p_ctr, ctr0, 16);
}

AES_CTR_context::~AES_CTR_context() {
  free(this->p_key);
  free(this->p_ctr);
}



///////////////////////////////////////////////////////////////////////////////
////////////////////////////    Filenode     //////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
Filenode::Filenode(const std::string &filename, const size_t block_size) {
  this->filename = filename;
  this->block_size = block_size;

  this->plain = new std::vector<std::vector<char>*>();
  this->cipher = new std::vector<std::vector<char>*>();
  this->aes_ctr_ctxs = new std::vector<AES_CTR_context*>();
}

Filenode::~Filenode() {
  for (auto it = this->plain->begin(); it != this->plain->end(); ) {
    delete * it;
    it = this->plain->erase(it);
  }
  delete this->plain;

  for (auto it = this->cipher->begin(); it != this->cipher->end(); ) {
    delete * it;
    it = this->cipher->erase(it);
  }
  delete this->cipher;


  for (auto it = this->aes_ctr_ctxs->begin(); it != this->aes_ctr_ctxs->end(); ) {
    delete * it;
    it = this->aes_ctr_ctxs->erase(it);
  }
  delete this->aes_ctr_ctxs;
}


size_t Filenode::size() {
  if (this->plain->empty())
    return 0;

  size_t size = (this->plain->size() - 1) * this->block_size;
  size += this->plain->back()->size();
  return size;
}

size_t Filenode::write(const long offset, const size_t data_size, const char *data) {
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
    Filenode::encrypt_block(block_index);
    written += bytes_to_write;
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
    Filenode::encrypt_block(this->plain->size()-1);
    written += bytes_to_write;
  }

  return written;
}

size_t Filenode::read(const long offset, const size_t buffer_size, char *buffer) {
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


size_t Filenode::metadata_size() {
  return 36;
}

size_t Filenode::dump_metadata(const size_t buffer_size, char *buffer) {
  std::string text = "This is a metadata file in plaintext"; // must be encryption key
  memcpy(buffer, (char*)text.c_str(), buffer_size);
  return buffer_size;
}


size_t Filenode::encrypt_block(const size_t block_index) {
  if (block_index < this->aes_ctr_ctxs->size()) { // already exists
    delete this->aes_ctr_ctxs->at(block_index);
    this->aes_ctr_ctxs->at(block_index) = new AES_CTR_context();
  } else {
    this->cipher->push_back(new std::vector<char>(this->plain->back()->size()));
    this->aes_ctr_ctxs->push_back(new AES_CTR_context());
  }
  std::vector<char> *plain_block = this->plain->at(block_index);
  std::vector<char> *cipher_block = this->cipher->at(block_index);
  AES_CTR_context *ctx = this->aes_ctr_ctxs->at(block_index);

  uint8_t ctr[16];
  std::memcpy(ctr, ctx->p_ctr, sizeof(ctx->p_ctr));
  sgx_aes_ctr_encrypt(ctx->p_key, (uint8_t*)&(*plain_block)[0], plain_block->size(),
                        ctr, 64, (uint8_t*)&(*cipher_block)[0]);
}

// size_t Filenode::dump_encryption(const size_t buffer_size, char *buffer) {
//   size_t encrypted = 0;
//   for (size_t index = 0;
//         index < this->plain->size() && encrypted < buffer_size; index++) {
//     std::vector<char> *block = this->plain->at(index);
//     auto size_to_encrypt = buffer_size - encrypted;
//     if (size_to_encrypt > block->size()) {
//       size_to_encrypt = block->size();
//     }
//     std::memcpy(buffer + read, &(*block)[0] + offset_in_block, size_to_copy);
//     read += size_to_encrypt + /*overhead*/;
//   }
//
//   return (int)read;
// }
