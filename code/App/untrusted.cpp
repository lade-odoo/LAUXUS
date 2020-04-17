#include "../utils/serialization.hpp"

#include "../flag.h"
#if EMULATING
#  include "untrusted.hpp"
#  define EMUL_API Untrusted::
#else
#  include "Enclave_u.h"
#  define EMUL_API
#endif

#include <stdio.h>
#include <string>




// OCall implementations
void EMUL_API ocall_print(const char* str) {
  printf("%s\n", str);
}


int EMUL_API ocall_dump(const char *path, const size_t size, const char *buffer) {
  return dump(path, size, buffer);
}

int EMUL_API ocall_dump_in_dir(const char *dir, const char *file, const size_t size, const char *buffer) {
  std::string path(dir); path.append("/"); path.append(file);
  return dump(path, size, buffer);
}

int EMUL_API ocall_dump_append_in_dir(const char *dir, const char *file, const size_t size, const char *buffer) {
  std::string path(dir); path.append("/"); path.append(file);
  return dump_append(path, size, buffer);
}

int EMUL_API ocall_dump_with_offset_in_dir(const char *dir, const char *file, const long offset, const size_t size, const char *buffer) {
  std::string path(dir); path.append("/"); path.append(file);
  return dump_with_offset(path, offset, size, buffer);
}


int EMUL_API ocall_file_size(const char *dir, const char *uuid) {
  std::string path(dir); path.append("/"); path.append(uuid);
  return file_size(path);
}

int EMUL_API ocall_load_file(const char *dir, const char *uuid, const long offset, const size_t size, char *buffer) {
  std::string path(dir); path.append("/"); path.append(uuid);
  return load_with_offset(path, offset, size, buffer);
}


int EMUL_API ocall_delete_from_dir(const char *dir, const char *uuid) {
  std::string path(dir); path.append("/"); path.append(uuid);
  return delete_file(path);
}
