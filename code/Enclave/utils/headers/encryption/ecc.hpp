#ifndef _ECC_HPP_
#define _ECC_HPP_

#include "../../../../flag.h"
#if EMULATING
#   include "../../../../tests/SGX_Emulator/sgx_tcrypto.hpp"
#   include "../../../../tests/SGX_Emulator/sgx_trts.hpp"
#else
#   include "sgx_tcrypto.h"
#   include "sgx_trts.h"
#endif


int lauxus_generate_ECC_keys(sgx_ec256_public_t *pk, sgx_ec256_private_t *sk);

int lauxus_sign_challenge(const size_t challenge_size, const uint8_t *challenge,
                const sgx_ec256_private_t *sk, sgx_ec256_signature_t *sig);

int lauxus_validate_signature(const size_t challenge_size, const uint8_t *challenge,
                sgx_ec256_public_t *pk, sgx_ec256_signature_t *sig);


#endif /*__ECC_HPP__*/
