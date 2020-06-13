#include "sgx_utils.hpp"


sgx_status_t sgx_create_enclave(const char *file_name, const int debug, sgx_launch_token_t *launch_token,
      int *launch_token_updated, sgx_enclave_id_t *enclave_id, sgx_misc_attribute_t *misc_attr) {
  return SGX_SUCCESS;
}

sgx_status_t sgx_destroy_enclave(const sgx_enclave_id_t enclave_id) {
  return SGX_SUCCESS;
}
