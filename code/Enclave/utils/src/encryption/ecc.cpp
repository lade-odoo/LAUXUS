#include "../../headers/encryption/ecc.hpp"


int lauxus_generate_ECC_keys(sgx_ec256_public_t *pk, sgx_ec256_private_t *sk) {
  sgx_ecc_state_handle_t ecc_handle;

  sgx_status_t status = sgx_ecc256_open_context(&ecc_handle);
  if (status != SGX_SUCCESS)
    goto err;

  status = sgx_ecc256_create_key_pair(sk, pk, ecc_handle);
  if (status != SGX_SUCCESS)
    goto err;

  status = sgx_ecc256_close_context(ecc_handle);
  if (status != SGX_SUCCESS)
    goto err;

  return 0;

err:
  if (ecc_handle != NULL)
    sgx_ecc256_close_context(ecc_handle);
  return -1;
}

int lauxus_sign_challenge(const size_t challenge_size, const uint8_t *challenge,
                const sgx_ec256_private_t *sk, sgx_ec256_signature_t *sig) {
  sgx_ecc_state_handle_t ecc_handle;

  sgx_status_t status = sgx_ecc256_open_context(&ecc_handle);
  if (status != SGX_SUCCESS)
    goto err;

  status = sgx_ecdsa_sign(challenge, challenge_size, (sgx_ec256_private_t*)sk, sig, ecc_handle);
  if (status != SGX_SUCCESS)
    goto err;

  status = sgx_ecc256_close_context(ecc_handle);
  if (status != SGX_SUCCESS)
    goto err;

  return 0;

err:
  if (ecc_handle != NULL)
    sgx_ecc256_close_context(ecc_handle);
  return -1;
}

int lauxus_validate_signature(const size_t challenge_size, const uint8_t *challenge,
                sgx_ec256_public_t *pk, sgx_ec256_signature_t *sig) {
  sgx_ecc_state_handle_t ecc_handle;

  sgx_status_t status = sgx_ecc256_open_context(&ecc_handle);
  if (status != SGX_SUCCESS)
    goto err;

  uint8_t result;
  status = sgx_ecdsa_verify(challenge, challenge_size, pk, sig, &result, ecc_handle);
  if (status != SGX_SUCCESS || result == SGX_EC_INVALID_SIGNATURE)
    goto err;

  status = sgx_ecc256_close_context(ecc_handle);
  if (status != SGX_SUCCESS)
    goto err;

  return 0;

err:
  if (ecc_handle != NULL)
    sgx_ecc256_close_context(ecc_handle);
  return -1;
}

int lauxus_shared_secret(sgx_ec256_private_t *sk, sgx_ec256_public_t *pk, sgx_ec256_dh_shared_t *shared) {
  sgx_ecc_state_handle_t ecc_handle;

  sgx_status_t status = sgx_ecc256_open_context(&ecc_handle);
  if (status != SGX_SUCCESS)
    goto err;

  uint8_t result;
  status = sgx_ecc256_compute_shared_dhkey(sk, pk, shared, ecc_handle);
  if (status != SGX_SUCCESS)
    goto err;

  status = sgx_ecc256_close_context(ecc_handle);
  if (status != SGX_SUCCESS)
    goto err;

  return 0;

err:
  if (ecc_handle != NULL)
    sgx_ecc256_close_context(ecc_handle);
  return -1;
}
