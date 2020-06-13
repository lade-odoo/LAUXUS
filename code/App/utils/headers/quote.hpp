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

#include "curl.hpp"
#include "base64.h"
#include "../../sgx_utils/sgx_utils.h"
#include <stdlib.h>
#include <cstring>

extern sgx_enclave_id_t ENCLAVE_ID;

const string QUOTE_VERIFY_URL = "https://api.trustedservices.intel.com/sgx/dev/attestation/v4/report";


sgx_quote_t* sgx_generate_quote(const sgx_ec256_public_t *pk_eu, uint32_t *quote_size);
sgx_ec256_public_t *sgx_verify_quote(uint32_t b64_quote_size, const uint8_t *b64_quote); // returns pk_e of the one that generated the quote


#endif /*_LAUXUS_QUOTE_HPP_*/
