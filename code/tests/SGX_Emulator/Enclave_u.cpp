#include "Enclave_u.hpp"


sgx_status_t sgx_new_user_keys(sgx_enclave_id_t eid, int *ret, sgx_ec256_public_t *pk_u, sgx_ec256_private_t *sk_u) {
  *ret = ECALLS::sgx_new_user_keys(pk_u, sk_u);
  return SGX_SUCCESS;
}

sgx_status_t sgx_new_filesystem(sgx_enclave_id_t eid, int *ret, const char *content_dir, const char* meta_dir, const char *audit_dir) {
  *ret = ECALLS::sgx_new_filesystem(content_dir, meta_dir, audit_dir);
  return SGX_SUCCESS;
}
sgx_status_t sgx_load_filesystem(sgx_enclave_id_t eid, int *ret, const sgx_sealed_data_t* rk_sealed_data, size_t rk_sealed_size,
              const sgx_sealed_data_t* ark_sealed_data, size_t ark_sealed_size,
              const uint8_t *e_supernode, size_t e_supernode_size,
              const char *content_dir, const char* meta_dir, const char *audit_dir) {
  *ret = ECALLS::sgx_load_filesystem(rk_sealed_data, rk_sealed_size, ark_sealed_data, ark_sealed_size,
            e_supernode, e_supernode_size, content_dir, meta_dir, audit_dir);
  return SGX_SUCCESS;
}
sgx_status_t sgx_destroy_filesystem(sgx_enclave_id_t eid, int *ret, const char *rk_path, const char *ark_path) {
  *ret = ECALLS::sgx_destroy_filesystem(rk_path, ark_path);
  return SGX_SUCCESS;
}


sgx_status_t sgx_login(sgx_enclave_id_t eid, int *ret, const sgx_ec256_private_t *sk_u, const lauxus_uuid_t *u_uuid) {
  *ret = ECALLS::sgx_login(sk_u, u_uuid);
  return SGX_SUCCESS;
}


sgx_status_t sgx_add_user(sgx_enclave_id_t eid, int *ret, const char *username, const sgx_ec256_public_t *pk_u, lauxus_uuid_t *u_uuid) {
  *ret = ECALLS::sgx_add_user(username, pk_u, u_uuid);
  return SGX_SUCCESS;
}
sgx_status_t sgx_remove_user(sgx_enclave_id_t eid, int *ret, const lauxus_uuid_t *u_uuid) {
  *ret = ECALLS::sgx_remove_user(u_uuid);
  return SGX_SUCCESS;
}
sgx_status_t sgx_edit_user_entitlement(sgx_enclave_id_t eid, int *ret, const char *path, lauxus_right_t rights, const lauxus_uuid_t *u_uuid) {
  *ret = ECALLS::sgx_edit_user_entitlement(path, rights, u_uuid);
  return SGX_SUCCESS;
}


/*********************** Data Plane related ECALLS ***********************/
sgx_status_t sgx_get_user_entitlement(sgx_enclave_id_t eid, int *ret, const char *path, lauxus_right_t *rights) {
  *ret = ECALLS::sgx_get_user_entitlement(path, rights);
  return SGX_SUCCESS;
}

sgx_status_t sgx_ls_buffer_size(sgx_enclave_id_t eid, int *ret, const char *path) {
  *ret = ECALLS::sgx_ls_buffer_size(path);
  return SGX_SUCCESS;
}
sgx_status_t sgx_readdir(sgx_enclave_id_t eid, int *ret, const char *path, char separator, size_t buffer_size, char *buffer) {
  *ret = ECALLS::sgx_readdir(path, separator, buffer_size, buffer);
  return SGX_SUCCESS;
}

sgx_status_t sgx_entry_type(sgx_enclave_id_t eid, int *ret, const char *path) {
  *ret = ECALLS::sgx_entry_type(path);
  return SGX_SUCCESS;
}
sgx_status_t sgx_get_times(sgx_enclave_id_t eid, int *ret, const char *path, time_t *atime, time_t *mtime, time_t *ctime) {
  *ret = ECALLS::sgx_get_times(path, atime, mtime, ctime);
  return SGX_SUCCESS;
}

sgx_status_t sgx_file_size(sgx_enclave_id_t eid, int *ret, const char *filepath) {
  *ret = ECALLS::sgx_file_size(filepath);
  return SGX_SUCCESS;
}
sgx_status_t sgx_open_file(sgx_enclave_id_t eid, int *ret, const char *filepath, lauxus_right_t asked_rights) {
  *ret = ECALLS::sgx_open_file(filepath, asked_rights);
  return SGX_SUCCESS;
}
sgx_status_t sgx_close_file(sgx_enclave_id_t eid, int *ret, const char *filepath) {
  *ret = ECALLS::sgx_close_file(filepath);
  return SGX_SUCCESS;
}
sgx_status_t sgx_create_file(sgx_enclave_id_t eid, int *ret, const char *reason, const char *filepath) {
  *ret = ECALLS::sgx_create_file(reason, filepath);
  return SGX_SUCCESS;
}
sgx_status_t sgx_read_file(sgx_enclave_id_t eid, int *ret, const char *reason, const char *filepath, long offset, size_t buffer_size, uint8_t *buffer) {
  *ret = ECALLS::sgx_read_file(reason, filepath, offset, buffer_size, buffer);
  return SGX_SUCCESS;
}
sgx_status_t sgx_write_file(sgx_enclave_id_t eid, int *ret, const char *reason, const char *filepath, long offset, size_t data_size, const uint8_t *data) {
  *ret = ECALLS::sgx_write_file(reason, filepath, offset, data_size, data);
  return SGX_SUCCESS;
}
sgx_status_t sgx_unlink(sgx_enclave_id_t eid, int *ret, const char *reason, const char *filepath) {
  *ret = ECALLS::sgx_unlink(reason, filepath);
  return SGX_SUCCESS;
}

sgx_status_t sgx_mkdir(sgx_enclave_id_t eid, int *ret, const char *reason, const char *dirpath) {
  *ret = ECALLS::sgx_unlink(reason, dirpath);
  return SGX_SUCCESS;
}
sgx_status_t sgx_rmdir(sgx_enclave_id_t eid, int *ret, const char *reason, const char *dirpath) {
  *ret = ECALLS::sgx_unlink(reason, dirpath);
  return SGX_SUCCESS;
}
