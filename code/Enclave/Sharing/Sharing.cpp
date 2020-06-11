#include "Enclave_t.h"
#include "sgx_utils.h"
#include "sgx_tseal.h"
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
