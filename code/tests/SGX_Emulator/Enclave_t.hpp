#ifndef __ENCLAVE_T_HPP__
#define __ENCLAVE_T_HPP__

#include "sgx_error.hpp"
#include "../../App/ocalls.hpp"

#include <cstddef>


sgx_status_t ocall_get_current_time(int *ret, time_t *time);

sgx_status_t ocall_dump(int *ret, const char *path, size_t size, const uint8_t *content);
sgx_status_t ocall_dump_in_dir(int *ret, const char *dir, const lauxus_uuid_t *u_uuid, size_t size, const uint8_t *content);
sgx_status_t ocall_dump_append_in_dir(int *ret, const char *dir, const lauxus_uuid_t *u_uuid, size_t size, const uint8_t *content);
sgx_status_t ocall_dump_with_offset_in_dir(int *ret, const char *dir, const lauxus_uuid_t *u_uuid, long offset, size_t size, const uint8_t *content);

sgx_status_t ocall_load_file(int *ret, const char *dir, const lauxus_uuid_t *u_uuid, long offset, size_t size, uint8_t *content);

sgx_status_t ocall_file_size(int *ret, const char *dir, const lauxus_uuid_t *u_uuid);

sgx_status_t ocall_delete_from_dir(int *ret, const char *dir, const lauxus_uuid_t *u_uuid);


#endif /*__ENCLAVE_T_HPP__*/
