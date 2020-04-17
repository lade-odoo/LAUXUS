#ifndef __UNTRUSTED_HPP__
#define __UNTRUSTED_HPP__

#include "../flag.h"
#if EMULATING
  namespace Untrusted {
#endif

  void ocall_print(const char* str);

  int ocall_dump(const char *path, const size_t size, const char *buffer);
  int ocall_dump_in_dir(const char *dir, const char *file, const size_t size, const char *buffer);
  int ocall_dump_append_in_dir(const char *dir, const char *file, const size_t size, const char *buffer);
  int ocall_dump_with_offset_in_dir(const char *dir, const char *file, const long offset, const size_t size, const char *buffer);

  int ocall_file_size(const char *dir, const char *uuid);
  int ocall_load_file(const char *dir, const char *uuid, const long offset, const size_t size, char *buffer);

  int ocall_delete_from_dir(const char *dir, const char *uuid);

#if EMULATING
  }
#endif

#endif /*__UNTRUSTED_HPP__*/
