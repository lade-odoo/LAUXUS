#ifndef __ECALLS_HPP__
#define __ECALLS_HPP__

#include "../flag.h"
#if EMULATING
#   include "../tests/SGX_Emulator/Enclave_t.hpp"
#   include "../tests/SGX_Emulator/sgx_tseal.hpp"
#   include "../tests/SGX_Emulator/sgx_trts.hpp"
#   define EMUL_EAPI ECALLS::
#else
#   include "Enclave_t.h"
#   include "sgx_tseal.h"
#   include "sgx_trts.h"
#   define EMUL_EAPI
#endif

#include "utils/headers/uuid.hpp"
#include "utils/headers/filesystem.hpp"
#include "utils/headers/encryption/ecc.hpp"
#include "utils/headers/encryption/aes_gcm.hpp"
#include "../utils/headers/rights.hpp"

#include <cerrno>
#include <string>

using namespace std;

#if EMULATING
  namespace ECALLS {
#endif


int sgx_new_user_keys(sgx_ec256_public_t *pk_u, sgx_ec256_private_t *sk_u);

int sgx_new_filesystem(const char *content_dir, const char* meta_dir, const char *audit_dir);
int sgx_load_filesystem(const sgx_sealed_data_t* rk_sealed_data, size_t rk_sealed_size,
          const sgx_sealed_data_t* ark_sealed_data, size_t ark_sealed_size,
          const uint8_t *e_supernode, size_t e_supernode_size,
          const char *content_dir, const char* meta_dir, const char *audit_dir);
int sgx_destroy_filesystem(const char *rk_path, const char *ark_path);

int sgx_login(const sgx_ec256_private_t *sk_u, const lauxus_uuid_t *u_uuid);

int sgx_add_user(const char *username, const sgx_ec256_public_t *pk_u, lauxus_uuid_t *u_uuid);
int sgx_remove_user(const lauxus_uuid_t *u_uuid);
int sgx_edit_user_entitlement(const char *path, lauxus_right_t rights, const lauxus_uuid_t *u_uuid);

/************************* Data Plane related ECALLS *************************/
int sgx_get_user_entitlement(const char *path, lauxus_right_t *rights);
int sgx_ls_buffer_size(const char *path);
int sgx_readdir(const char *path, char separator, size_t buffer_size, char *buffer);


int sgx_entry_type(const char *path);
int sgx_get_times(const char *path, time_t *atime, time_t *mtime, time_t *ctime);

int sgx_file_size(const char *filepath);
int sgx_open_file(const char *filepath, lauxus_right_t asked_rights);
int sgx_close_file(const char *filepath);
int sgx_create_file(const char *reason, const char *filepath);
int sgx_read_file(const char *reason, const char *filepath, long offset, size_t buffer_size, uint8_t *buffer);
int sgx_write_file(const char *reason, const char *filepath, long offset, size_t data_size, const uint8_t *data);
int sgx_truncate_file(const char *filepath);
int sgx_unlink(const char *reason, const char *filepath);

int sgx_mkdir(const char *reason, const char *dirpath);
int sgx_rmdir(const char *reason, const char *dirpath);


#if EMULATING
  }
#endif

#endif /*__ECALLS_HPP__*/
