#ifndef __ENCLAVE_U_HPP__
#define __ENCLAVE_U_HPP__

#include "time.h"
#include "../../utils/headers/rights.hpp"
#include "../../Enclave/utils/headers/encryption/aes_gcm.hpp"
#include "../../Enclave/utils/headers/uuid.hpp"

#include "sgx_utils.hpp"
#include "sgx_tseal.hpp"
#include "sgx_error.hpp"
#include "../../Enclave/ecalls.hpp"


sgx_status_t sgx_new_user_keys(sgx_enclave_id_t eid, int *ret, sgx_ec256_public_t *pk_u, sgx_ec256_private_t *sk_u);

sgx_status_t sgx_new_filesystem(sgx_enclave_id_t eid, int *ret, const char *content_dir, const char* meta_dir, const char *audit_dir);
sgx_status_t sgx_load_filesystem(sgx_enclave_id_t eid, int *ret, const sgx_sealed_data_t* rk_sealed_data, size_t rk_sealed_size,
              const sgx_sealed_data_t* ark_sealed_data, size_t ark_sealed_size,
              const uint8_t *e_supernode, size_t e_supernode_size,
              const char *content_dir, const char* meta_dir, const char *audit_dir);
sgx_status_t sgx_destroy_filesystem(sgx_enclave_id_t eid, int *ret, const char *rk_path, const char *ark_path);


sgx_status_t sgx_login(sgx_enclave_id_t eid, int *ret, const sgx_ec256_private_t *sk_u, const lauxus_uuid_t *u_uuid);


sgx_status_t sgx_add_user(sgx_enclave_id_t eid, int *ret, const char *username, const sgx_ec256_public_t *pk_u, lauxus_uuid_t *u_uuid);
sgx_status_t sgx_remove_user(sgx_enclave_id_t eid, int *ret, const lauxus_uuid_t *u_uuid);
sgx_status_t sgx_edit_user_entitlement(sgx_enclave_id_t eid, int *ret, const char *path, lauxus_right_t rights, const lauxus_uuid_t *u_uuid);


/*********************** Data Plane rselated ECALLS ***********************/
sgx_status_t sgx_get_user_entitlement(sgx_enclave_id_t eid, int *ret, const char *path, lauxus_right_t *rights);

sgx_status_t sgx_ls_buffer_size(sgx_enclave_id_t eid, int *ret, const char *path);
sgx_status_t sgx_readdir(sgx_enclave_id_t eid, int *ret, const char *path, char separator, size_t buffer_size, char *buffer);

sgx_status_t sgx_entry_type(sgx_enclave_id_t eid, int *ret, const char *path);
sgx_status_t sgx_get_times(sgx_enclave_id_t eid, int *ret, const char *path, time_t *atime, time_t *mtime, time_t *ctime);

sgx_status_t sgx_file_size(sgx_enclave_id_t eid, int *ret, const char *filepath);
sgx_status_t sgx_open_file(sgx_enclave_id_t eid, int *ret, const char *filepath, lauxus_right_t asked_rights);
sgx_status_t sgx_close_file(sgx_enclave_id_t eid, int *ret, const char *filepath);
sgx_status_t sgx_create_file(sgx_enclave_id_t eid, int *ret, const char *reason, const char *filepath);
sgx_status_t sgx_read_file(sgx_enclave_id_t eid, int *ret, const char *reason, const char *filepath, long offset, size_t buffer_size, uint8_t *buffer);
sgx_status_t sgx_write_file(sgx_enclave_id_t eid, int *ret, const char *reason, const char *filepath, long offset, size_t data_size, const uint8_t *data);
sgx_status_t sgx_truncate_file(sgx_enclave_id_t eid, int *ret, const char *filepath);
sgx_status_t sgx_unlink(sgx_enclave_id_t eid, int *ret, const char *reason, const char *filepath);

sgx_status_t sgx_mkdir(sgx_enclave_id_t eid, int *ret, const char *reason, const char *dirpath);
sgx_status_t sgx_rmdir(sgx_enclave_id_t eid, int *ret, const char *reason, const char *dirpath);

#endif /*__ENCLAVE_U_HPP__*/
