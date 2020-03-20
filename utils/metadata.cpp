#include "../utils/metadata.hpp"

#include <cerrno>
#include <string>
#include <cstring>
#include <vector>


///////////////////////////////////////////////////////////////////////////////
////////////////////////////    Filenode     //////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
Filenode::Filenode(const std::string &filename, const size_t block_size) {
  this->filename = filename;
  this->block_size = block_size;

  this->blocks = new std::vector<std::vector<char>*>();
}

Filenode::~Filenode() {
  auto block = this->blocks->begin();
  while (block != this->blocks->end()) {
    block = this->blocks->erase(block);
  }

  delete this->blocks; this->blocks = NULL;
}


size_t Filenode::size() {
  if (this->blocks->empty())
    return 0;

  size_t size = (this->blocks->size() - 1) * this->block_size;
  size += this->blocks->back()->size();
  return size;
}

size_t Filenode::write(const long offset, const size_t data_size, const char *data) {
  size_t written = 0;
  size_t offset_in_block = offset % block_size;
  size_t block_index = (size_t)((offset-offset_in_block)/this->block_size);

  // fill as much as we can inside available blocks
  if (block_index < this->blocks->size()) {
    std::vector<char> *block = this->blocks->at(block_index);
    size_t bytes_to_write = data_size;
    if (this->block_size < (offset_in_block + data_size)) {
      bytes_to_write = this->block_size - offset_in_block;
      block->resize(this->block_size);
    } else {
      block->resize(offset_in_block + data_size);
    }
    std::memcpy(&(*block)[0] + offset_in_block, data, bytes_to_write);
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
    this->blocks->push_back(block);
    written += bytes_to_write;
  }

  return written;
}

size_t Filenode::read(const long offset, const size_t buffer_size, char *buffer) {
  size_t read = 0;
  size_t offset_in_block = offset % this->block_size;
  size_t block_index = (size_t)((offset-offset_in_block)/this->block_size);

  if (this->blocks->size() <= block_index)
    return 0;

  for (size_t index = block_index;
       index < this->blocks->size() && read < buffer_size;
       index++, offset_in_block = 0) {
    std::vector<char> *block = this->blocks->at(index);
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
  std::string text = "This is a metadata file in plaintext";
  memcpy(buffer, (char*)text.c_str(), buffer_size);
  return buffer_size;
}
