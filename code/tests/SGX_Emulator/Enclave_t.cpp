#include "Enclave_t.hpp"


sgx_status_t ocall_get_current_time(int *ret, time_t *time) {
  *ret = OCALLS::ocall_get_current_time(time);
  return SGX_SUCCESS;
}

sgx_status_t ocall_dump(int *ret, const char *path, size_t size, const uint8_t *content) {
  *ret = OCALLS::ocall_dump(path, size, content);
  return SGX_SUCCESS;
}
sgx_status_t ocall_dump_in_dir(int *ret, const char *dir, const lauxus_uuid_t *n_uuid, size_t size, const uint8_t *content) {
  *ret = OCALLS::ocall_dump_in_dir(dir, n_uuid, size, content);
  return SGX_SUCCESS;
}
sgx_status_t ocall_dump_append_in_dir(int *ret, const char *dir, const lauxus_uuid_t *n_uuid, size_t size, const uint8_t *content) {
  *ret = OCALLS::ocall_dump_append_in_dir(dir, n_uuid, size, content);
  return SGX_SUCCESS;
}
sgx_status_t ocall_dump_with_offset_in_dir(int *ret, const char *dir, const lauxus_uuid_t *n_uuid, long offset, size_t size, const uint8_t *content) {
  *ret = OCALLS::ocall_dump_with_offset_in_dir(dir, n_uuid, offset, size, content);
  return SGX_SUCCESS;
}

sgx_status_t ocall_load_file(int *ret, const char *dir, const lauxus_uuid_t *n_uuid, long offset, size_t size, uint8_t *content) {
  *ret = OCALLS::ocall_load_file(dir, n_uuid, offset, size, content);
  return SGX_SUCCESS;
}

sgx_status_t ocall_file_size(int *ret, const char *dir, const lauxus_uuid_t *n_uuid) {
  *ret = OCALLS::ocall_file_size(dir, n_uuid);
  return SGX_SUCCESS;
}

sgx_status_t ocall_delete_from_dir(int *ret, const char *dir, const lauxus_uuid_t *n_uuid) {
  *ret = OCALLS::ocall_delete_from_dir(dir, n_uuid);
  return SGX_SUCCESS;
}
