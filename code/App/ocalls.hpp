#ifndef __OCALLS_HPP__
#define __OCALLS_HPP__

#include "../flag.h"
#if EMULATING
#   include "../tests/SGX_Emulator/Enclave_u.hpp"
#   define EMUL_API OCALLS::
#else
#   include "Enclave_u.h"
#   define EMUL_API
#endif

#include <stdio.h>
#include <ctime>
#include <string>
#include <cstring>

using namespace std;

#if EMULATING
  namespace OCALLS {
#endif


void ocall_print(const char* str);

int ocall_get_current_time(time_t *ret_time);

int ocall_dump(const char *path, size_t size, const uint8_t *content);
int ocall_dump_in_dir(const char *dir, const lauxus_uuid_t *n_uuid, size_t size, const uint8_t *content);
int ocall_dump_append_in_dir(const char *dir, const lauxus_uuid_t *n_uuid, size_t size, const uint8_t *content);
int ocall_dump_with_offset_in_dir(const char *dir, const lauxus_uuid_t *n_uuid, long offset, size_t size, const uint8_t *content);

int ocall_load_file(const char *dir, const lauxus_uuid_t *n_uuid, long offset, size_t size, uint8_t *content);

int ocall_file_size(const char *dir, const lauxus_uuid_t *n_uuid);

int ocall_delete_from_dir(const char *dir, const lauxus_uuid_t *n_uuid);


#if EMULATING
  }
#endif

#endif /*__OCALLS_HPP__*/
