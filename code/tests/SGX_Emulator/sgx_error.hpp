#ifndef _SGX_ERROR_H_
#define _SGX_ERROR_H_

typedef enum _status_t {
  SGX_SUCCESS = 0,
  SGX_ERROR_MAC_MISMATCH = -1,
  SGX_ERROR_INVALID_PARAMETER = -2,
  SGX_ERROR_UNEXPECTED = -3
} sgx_status_t;

#endif
