#include "sgx_tcrypto.hpp"
#include "sgx_error.hpp"
#include "sgx_trts.hpp"

#include <string>
#include <cstring>
#include <cstdint>

using namespace std;


// AES CTR
sgx_status_t sgx_aes_ctr_encrypt(const sgx_aes_ctr_128bit_key_t *p_key,
          const uint8_t *p_src, const uint32_t src_len,
          uint8_t *p_ctr, const uint32_t ctr_inc_bits, uint8_t *p_dst) {

  size_t key_size = sizeof(sgx_aes_ctr_128bit_key_t);
  uint8_t xored[src_len];
  for(uint32_t i = 0; i < src_len; i++) {
    uint8_t a = ((uint8_t*)p_key)[i % key_size];
    uint8_t b = p_src[i];
    xored[i] = a^b;
  }

  memcpy(p_dst, xored, src_len);
  return SGX_SUCCESS;
}

sgx_status_t sgx_aes_ctr_decrypt(const sgx_aes_ctr_128bit_key_t *p_key,
          const uint8_t *p_src, const uint32_t src_len,
          uint8_t *p_ctr, const uint32_t ctr_inc_bits, uint8_t *p_dst) {

  return sgx_aes_ctr_encrypt(p_key, p_src, src_len, p_ctr, ctr_inc_bits, p_dst);
}

// AES GCM
sgx_status_t sgx_rijndael128GCM_encrypt(const sgx_aes_gcm_128bit_key_t *p_key,
          const uint8_t *p_src, uint32_t src_len, uint8_t *p_dst,
          const uint8_t *p_iv, uint32_t iv_len,
          const uint8_t *p_aad, uint32_t aad_len, sgx_aes_gcm_128bit_tag_t *p_out_mac) {

  size_t key_size = sizeof(sgx_aes_ctr_128bit_key_t);
  uint8_t xored[src_len];
  for(uint32_t i = 0; i < src_len; i++) {
    uint8_t a = ((uint8_t*)p_key)[i % key_size];
    uint8_t b = p_src[i];
    xored[i] = a^b;
  }

  size_t mac_size = sizeof(sgx_aes_gcm_128bit_tag_t);
  uint8_t mac[mac_size];
  for(uint32_t i = 0; i < mac_size; i++) {
    uint8_t a = 0x44;
    if (aad_len > 0)
      a = p_aad[i % aad_len];
    uint8_t b = xored[i % src_len];
    mac[i] = a^b;
  }

  memcpy(p_dst, xored, src_len);
  memcpy(p_out_mac, mac, mac_size);
  return SGX_SUCCESS;
}

sgx_status_t sgx_rijndael128GCM_decrypt(const sgx_aes_gcm_128bit_key_t *p_key,
          const uint8_t *p_src, uint32_t src_len, uint8_t *p_dst,
          const uint8_t *p_iv, uint32_t iv_len,
          const uint8_t *p_aad, uint32_t aad_len, const sgx_aes_gcm_128bit_tag_t *p_in_mac) {

  size_t mac_size = sizeof(sgx_aes_gcm_128bit_tag_t);
  uint8_t mac[mac_size];
  for(uint32_t i = 0; i < mac_size; i++) {
    uint8_t a = 0x44;
    if (aad_len > 0)
      a = p_aad[i % aad_len];
    uint8_t b = p_src[i % src_len];
    mac[i] = a^b;
  }
  if (memcmp(mac, p_in_mac, mac_size) != 0)
    return SGX_ERROR_MAC_MISMATCH;

  size_t key_size = sizeof(sgx_aes_ctr_128bit_key_t);
  uint8_t xored[src_len];
  for(uint32_t i = 0; i < src_len; i++) {
    uint8_t a = ((uint8_t*)p_key)[i % key_size];
    uint8_t b = p_src[i];
    xored[i] = a^b;
  }

  memcpy(p_dst, xored, src_len);
  return SGX_SUCCESS;
}

// ECC 256
sgx_status_t sgx_ecc256_open_context(sgx_ecc_state_handle_t* p_ecc_handle) {
  return SGX_SUCCESS;
}
sgx_status_t sgx_ecc256_close_context(sgx_ecc_state_handle_t ecc_handle) {
  return SGX_SUCCESS;
}

sgx_status_t sgx_ecc256_create_key_pair(sgx_ec256_private_t *p_private, sgx_ec256_public_t *p_public,
                                        sgx_ecc_state_handle_t ecc_handle) {
  sgx_read_rand((uint8_t*)p_public, sizeof(_sgx_ec256_public_t));
  memcpy(p_private, p_public, sizeof(sgx_ec256_private_t));
  return SGX_SUCCESS;
}

sgx_status_t sgx_ecdsa_sign(const uint8_t *p_data, uint32_t data_size,
                            sgx_ec256_private_t *p_private, sgx_ec256_signature_t *p_signature,
                            sgx_ecc_state_handle_t ecc_handle) {

  size_t key_size = sizeof(sgx_ec256_private_t);
  size_t sig_size = sizeof(sgx_ec256_signature_t);
  uint8_t xored[sig_size];
  for(uint32_t i = 0; i < sig_size; i++) {
    uint8_t a = ((uint8_t*)p_private)[i % key_size];
    uint8_t b = p_data[i % data_size];
    xored[i] = a^b;
  }

  memcpy(p_signature, xored, sig_size);
  return SGX_SUCCESS;
}

sgx_status_t sgx_ecdsa_verify(const uint8_t *p_data, uint32_t data_size,
                            const sgx_ec256_public_t *p_public, sgx_ec256_signature_t *p_signature,
                            uint8_t *p_result, sgx_ecc_state_handle_t ecc_handle) {

  size_t key_size = sizeof(sgx_ec256_private_t);
  size_t sig_size = sizeof(sgx_ec256_signature_t);
  uint8_t xored[sig_size];
  for(uint32_t i = 0; i < sig_size; i++) {
    uint8_t a = ((uint8_t*)p_public)[i % key_size];
    uint8_t b = p_data[i % data_size];
    xored[i] = a^b;
  }

  if (memcmp(p_signature, xored, sig_size) == 0) {
    *p_result = SGX_EC_VALID;
    return SGX_SUCCESS;
  }
  *p_result = SGX_EC_INVALID_SIGNATURE;
  return SGX_ERROR_INVALID_PARAMETER;
}
