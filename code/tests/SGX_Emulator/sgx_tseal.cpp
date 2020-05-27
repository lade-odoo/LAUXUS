#include "sgx_tseal.hpp"


sgx_status_t sgx_seal_data(const uint32_t additional_MACtext_length,
    const uint8_t *p_additional_MACtext,
    const uint32_t text2encrypt_length,
    const uint8_t *p_text2encrypt,
    const uint32_t sealed_data_size,
    sgx_sealed_data_t *p_sealed_data) {
  return SGX_SUCCESS;
}

sgx_status_t sgx_unseal_data(const sgx_sealed_data_t *p_sealed_data,
    uint8_t *p_additional_MACtext,
    uint32_t *p_additional_MACtext_length,
    uint8_t *p_decrypted_text,
    uint32_t *p_decrypted_text_length) {
  return SGX_SUCCESS;
}
