#include "Enclave_u.h"
#include "sgx_urts.h"

#include "../utils/serialization.hpp"

#include <stdio.h>
#include <string>

using namespace std;

// extern string SUPERNODE_PATH;
// extern sgx_enclave_id_t ENCLAVE_ID;


// OCall implementations
void ocall_print(const char* str) {
  printf("%s\n", str);
}


int ocall_dump(const char *path, const size_t size, const char *buffer) {
  return dump(path, size, buffer);
}

int ocall_dump_in_dir(const char *dir, const char *file, const size_t size, const char *buffer) {
  string path(dir); path.append("/"); path.append(file);
  return dump(path, size, buffer);
}

int ocall_dump_append_in_dir(const char *dir, const char *file, const size_t size, const char *buffer) {
  string path(dir); path.append("/"); path.append(file);
  return dump_append(path, size, buffer);
}

int ocall_dump_with_offset_in_dir(const char *dir, const char *file, const size_t offset, const size_t size, const char *buffer) {
  string path(dir); path.append("/"); path.append(file);
  return dump_with_offset(path, offset, size, buffer);
}


int ocall_delete_from_dir(const char *dir, const char *path) {
  return delete_file(path);
}
