#ifndef _SGX_TRTS_H_
#define _SGX_TRTS_H_

#include "sgx_error.hpp"
#include <cstddef>


sgx_status_t sgx_read_rand(unsigned char *rand, size_t length_in_bytes);


#endif
