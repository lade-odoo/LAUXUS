#ifndef _SGX_UTILS_H_
#define _SGX_UTILS_H_

#include "sgx_error.hpp"
#include <stdint.h>

#define SGX_DEBUG_FLAG 0

typedef uint64_t sgx_enclave_id_t;
typedef uint8_t sgx_launch_token_t[1024];

typedef struct _attributes_t {
    uint64_t      flags;
    uint64_t      xfrm;
} sgx_attributes_t;

/* define MISCSELECT - all bits are currently reserved */
typedef uint32_t    sgx_misc_select_t;

typedef struct _sgx_misc_attribute_t {
    sgx_attributes_t    secs_attr;
    sgx_misc_select_t   misc_select;
} sgx_misc_attribute_t;


sgx_status_t sgx_create_enclave(const char *file_name,
                                       const int debug,
                                       sgx_launch_token_t *launch_token,
                                       int *launch_token_updated,
                                       sgx_enclave_id_t *enclave_id,
                                       sgx_misc_attribute_t *misc_attr);

sgx_status_t sgx_destroy_enclave(const sgx_enclave_id_t enclave_id);


#endif
