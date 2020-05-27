#ifndef SGX_UTILS_H_
#define SGX_UTILS_H_

#include <string>
#include <cstring>
#include <iostream>

#include "../flag.h"
#if EMULATING
#   include "../tests/SGX_Emulator/sgx_error.hpp"
#   include "../tests/SGX_Emulator/sgx_utils.hpp"
#else
#   include "sgx_urts.h"
#endif

using namespace std;


void print_error_message(sgx_status_t ret);

int initialize_enclave(sgx_enclave_id_t* eid, const string& launch_token_path, const string& enclave_name);

bool is_ecall_successful(sgx_status_t sgx_status, const string& err_msg, int ret_value=0);

#endif // SGX_UTILS_H_
