#ifndef __ENCLAVE_T_HPP__
#define __ENCLAVE_T_HPP__

#include "sgx_error.hpp"

#include <cstddef>


sgx_status_t ocall_dump(int *ret, const char *path, const size_t size, const char *buffer);
sgx_status_t ocall_dump_in_dir(int *ret, const char *dir, const char *file, const size_t size, const char *buffer);
sgx_status_t ocall_dump_append_in_dir(int *ret, const char *dir, const char *file, const size_t size, const char *buffer);
sgx_status_t ocall_dump_with_offset_in_dir(int *ret, const char *dir, const char *file, const long offset, const size_t size, const char *buffer);

sgx_status_t ocall_file_size(int *ret, const char *dir, const char *uuid);
sgx_status_t ocall_load_file(int *ret, const char *dir, const char *uuid, const long offset, const size_t size, char *buffer);

sgx_status_t ocall_delete_from_dir(int *ret, const char *dir, const char *uuid);


#endif /*__ENCLAVE_T_HPP__*/
