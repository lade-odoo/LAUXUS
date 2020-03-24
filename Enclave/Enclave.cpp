#include <cerrno>

#include "sgx_trts.h"
#include "sgx_tseal.h"
#include "Enclave_t.h"
#include "../utils/filesystem.hpp"
#include "../utils/encryption.hpp"

static FileSystem* FILE_SYSTEM;


int sgx_init_filesystem() {
  AES_GCM_context *root_key = new AES_GCM_context();
  FILE_SYSTEM = new FileSystem(root_key, FileSystem::DEFAULT_BLOCK_SIZE);
  return 0;
}
int sgx_init_existing_filesystem(size_t rk_sealed_size, const char *sealed_rk) {
  if (rk_sealed_size != AES_GCM_context::size()+sizeof(sgx_sealed_data_t))
    return -1;

  size_t plain_size = rk_sealed_size - sizeof(sgx_sealed_data_t);
  char plaintext[plain_size];
  sgx_status_t status = sgx_unseal_data((sgx_sealed_data_t*)sealed_rk, NULL, NULL, (uint8_t*)plaintext, (uint32_t*)&plain_size);
  if (status != SGX_SUCCESS)
    return -1;

  AES_GCM_context *root_key = new AES_GCM_context();
  root_key->load(plaintext);
  FILE_SYSTEM = new FileSystem(root_key, FileSystem::DEFAULT_BLOCK_SIZE);
  return 0;
}


int sgx_destroy_filesystem(size_t rk_sealed_size, char *sealed_rk) {
  if (FILE_SYSTEM == NULL || rk_sealed_size != AES_GCM_context::size()+sizeof(sgx_sealed_data_t))
    return -1;

  size_t plain_size = AES_GCM_context::size(); size_t seal_size = plain_size+sizeof(sgx_sealed_data_t);
  char plaintext[plain_size];
  FILE_SYSTEM->root_key->dump(plaintext);
  sgx_status_t status = sgx_seal_data(0, NULL, plain_size, (uint8_t*)plaintext, seal_size, (sgx_sealed_data_t*)sealed_rk);
  if (status != SGX_SUCCESS)
    return -1;

  delete FILE_SYSTEM;
  return 0;
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
