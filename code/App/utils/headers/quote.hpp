#ifndef _LAUXUS_QUOTE_HPP_
#define _LAUXUS_QUOTE_HPP_

#include "../../../flag.h"
#if EMULATING
#   include "../../../tests/SGX_Emulator/sgx_tcrypto.hpp"
#else
#   include "Enclave_u.h"
#   include "sgx_tcrypto.h"
#   include "sgx_uae_service.h"
#endif

#include "../../sgx_utils/sgx_utils.h"
#include <stdlib.h>
#include <cstring>

extern sgx_enclave_id_t ENCLAVE_ID;


sgx_quote_t* sgx_generate_quote(const sgx_ec256_public_t *pk_eu, uint32_t *quote_size);


#endif /*_LAUXUS_QUOTE_HPP_*/
