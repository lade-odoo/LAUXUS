#include "Enclave_t.h"
#include "sgx_utils.h"
#include "sgx_tseal.h"
#include "../utils/headers/encryption/aes_ctr.hpp"
#include "../utils/headers/encryption/ecc.hpp"

#include <cstring>

using namespace std;


int sgx_generate_report(const sgx_ec256_public_t *pk_eu, const sgx_target_info_t *info, sgx_report_t *report) {
  sgx_report_data_t report_data = { 0 }; bzero(&report_data, sizeof(report_data));
  memcpy(report_data.d, pk_eu, sizeof(sgx_ec256_public_t)); // report data must be 64 bytes long

  sgx_status_t status = sgx_create_report(info, &report_data, report);
  if (status != SGX_SUCCESS)
    return -1;
  return 0;
}

int sgx_get_shared_rk(size_t e_rk_size, uint8_t *e_rk, sgx_ec256_public_t *pk_eph, size_t saled_rk_size, const sgx_sealed_data_t *sealed_rk, sgx_ec256_public_t *pk_eo) {
  if (e_rk_size != sizeof(lauxus_gcm_t))
    return -1;

  // generate ephemeral keys
  sgx_ec256_private_t sk_eph;
  if (lauxus_generate_ECC_keys(pk_eph, &sk_eph) < 0)
    return -1;

  // compute shared secret (sk_eph, pk_eo)
  sgx_ec256_dh_shared_t shared_eph;
  if (lauxus_shared_secret(&sk_eph, pk_eph, &shared_eph) < 0)
    return -1;

  // unseal root key
  lauxus_gcm_t root_key; uint32_t rk_size = sizeof(lauxus_gcm_t);
  if (sgx_unseal_data(sealed_rk, NULL, NULL, (uint8_t*)&root_key, &rk_size) != SGX_SUCCESS)
    return -1;

  // encrypt root key (sgx_ec256_dh_shared_t is 32 bytes -> lauxus_ctr_t also)
  if (sizeof(sgx_ec256_dh_shared_t) != sizeof(lauxus_ctr_t))
    return -1;
  if (lauxus_ctr_encrypt((lauxus_ctr_t*)&shared_eph, (uint8_t*)&root_key, e_rk_size, e_rk) < 0)
    return -1;

  return 0;
}



int sgx_sign_message(size_t size, const uint8_t *challenge, const sgx_ec256_private_t *sk, sgx_ec256_signature_t *sig) {
  return lauxus_sign_challenge(size, challenge, sk, sig);
}

int sgx_validate_signature(size_t size, const uint8_t *challenge, sgx_ec256_public_t *pk, sgx_ec256_signature_t *sig) {
  return lauxus_validate_signature(size, challenge, pk, sig);
}



int sgx_generate_sealed_keys(const char *sk_path, const char *pk_path) {
  // Generate ECC keys
  sgx_ec256_public_t pk; sgx_ec256_private_t sk;
  if (lauxus_generate_ECC_keys(&pk, &sk) < 0)
    return -1;

  // Seal private key
  size_t sk_seal_size = sizeof(sgx_ec256_private_t) + sizeof(sgx_sealed_data_t);
  uint8_t sealed_sk[sk_seal_size];
  if (sgx_seal_data(0, NULL, sizeof(sgx_ec256_private_t), (uint8_t*)&sk, sk_seal_size, (sgx_sealed_data_t*)sealed_sk) != SGX_SUCCESS)
    return -2;

  // Dump keys
  int ret = -1;
  if ((ocall_dump(&ret, sk_path, sk_seal_size, sealed_sk) != SGX_SUCCESS || ret < 0) ||
      (ocall_dump(&ret, pk_path, sizeof(sgx_ec256_public_t), (uint8_t*)&pk) != SGX_SUCCESS || ret < 0))
    return -3;

  return 0;
}
