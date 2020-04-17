#include "Enclave_t.hpp"
#include "../../App/untrusted.hpp"

#include <cstddef>


sgx_status_t ocall_dump(int *ret, const char *path, const size_t size, const char *buffer) {
  *ret = Untrusted::ocall_dump(path, size, buffer);
  return SGX_SUCCESS;
}

sgx_status_t ocall_dump_in_dir(int *ret, const char *dir, const char *file, const size_t size, const char *buffer) {
  *ret = Untrusted::ocall_dump_in_dir(dir, file, size, buffer);
  return SGX_SUCCESS;
}

sgx_status_t ocall_dump_append_in_dir(int *ret, const char *dir, const char *file, const size_t size, const char *buffer) {
  *ret = Untrusted::ocall_dump_append_in_dir(dir, file, size, buffer);
  return SGX_SUCCESS;
}

sgx_status_t ocall_dump_with_offset_in_dir(int *ret, const char *dir, const char *file, const long offset, const size_t size, const char *buffer) {
  *ret = Untrusted::ocall_dump_with_offset_in_dir(dir, file, offset, size, buffer);
  return SGX_SUCCESS;
}


sgx_status_t ocall_file_size(int *ret, const char *dir, const char *uuid) {
  *ret = Untrusted::ocall_file_size(dir, uuid);
  return SGX_SUCCESS;
}

sgx_status_t ocall_load_file(int *ret, const char *dir, const char *uuid, const long offset, const size_t size, char *buffer) {
  *ret = Untrusted::ocall_load_file(dir, uuid, offset, size, buffer);
  return SGX_SUCCESS;
}


sgx_status_t ocall_delete_from_dir(int *ret, const char *dir, const char *uuid) {
  *ret = Untrusted::ocall_delete_from_dir(dir, uuid);
  return SGX_SUCCESS;
}
