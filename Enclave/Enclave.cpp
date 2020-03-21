#include <cerrno>

#include "sgx_trts.h"
#include "sgx_tseal.h"
#include "Enclave_t.h"
#include "../utils/filesystem.hpp"

static FileSystem* FILE_SYSTEM;


int sgx_init_filesystem(const char* pathname) {
  FILE_SYSTEM = new FileSystem(pathname, FileSystem::DEFAULT_BLOCK_SIZE);
  return 0;
}

int sgx_destroy_filesystem() {
  if (FILE_SYSTEM != NULL) {
    delete FILE_SYSTEM;
  }
  return -1;
}


int sgx_ls_buffer_size() {
  std::vector<std::string> files = FILE_SYSTEM->readdir();
  size_t size = 0;

  for (auto itr = files.begin(); itr != files.end(); itr++) {
    std::string name = (*itr);
    size += name.length() + 1;
  }
  return size;
}

int sgx_readdir(char separator, size_t buffer_size, char *buffer) {
  std::vector<std::string> files = FILE_SYSTEM->readdir();
  size_t offset = 0, count_entries = 0;

  for (auto itr = files.begin(); itr != files.end() && offset < buffer_size; itr++, count_entries++) {
    std::string name = (*itr);
    memcpy(buffer+offset, (char*)name.c_str(), name.length());
    buffer[offset+name.length()] = separator;
    offset += name.length() + 1;
  }

  return count_entries;
}


int sgx_isfile(const char *filename) {
  if (FILE_SYSTEM->isfile(filename))
    return EEXIST;
  return -ENOENT;
}

int sgx_file_size(const char *filename) {
  return FILE_SYSTEM->file_size(filename);
}

int sgx_create_file(const char *filename) {
  return FILE_SYSTEM->create_file(filename);
}

int sgx_read_file(const char *filename, long offset, size_t buffer_size, char *buffer) {
  return FILE_SYSTEM->read_file(filename, offset, buffer_size, buffer);
}

int sgx_write_file(const char *filename, long offset, size_t data_size, const char *data) {
  return FILE_SYSTEM->write_file(filename, offset, data_size, data);
}

int sgx_unlink(const char *filename) {
  return FILE_SYSTEM->unlink(filename);
}


int sgx_metadata_size(const char *filename) {
  return FILE_SYSTEM->metadata_size(filename);
}

int sgx_dump_metadata(const char *filename, size_t buffer_size, char *buffer) {
  return FILE_SYSTEM->dump_metadata(filename, buffer_size, buffer);
}

int sgx_load_metadata(const char *filename, size_t buffer_size, const char *buffer) {
  return FILE_SYSTEM->load_metadata(filename, buffer_size, buffer);
}


int sgx_encryption_size(const char *filename, long up_offset, size_t up_size) {
  return FILE_SYSTEM->encryption_size(filename, up_offset, up_size);
}

int sgx_dump_encryption(const char *filename, long up_offset, size_t up_size, size_t buffer_size, char *buffer) {
  return FILE_SYSTEM->dump_encryption(filename, up_offset, up_size, buffer_size, buffer);
}

int sgx_load_encryption(const char *filename, long offset, size_t buffer_size, const char *buffer) {
  return FILE_SYSTEM->load_encryption(filename, offset, buffer_size, buffer);
}
