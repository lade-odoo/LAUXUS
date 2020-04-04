#ifndef _SGX_TCRYPTO_H_
#define _SGX_TCRYPTO_H_

#include "sgx_error.hpp"
#include <cstdint>


#define SGX_AESCTR_KEY_SIZE             16
#define SGX_AESGCM_KEY_SIZE             16
#define SGX_AESGCM_MAC_SIZE             16


typedef uint8_t sgx_aes_ctr_128bit_key_t[SGX_AESCTR_KEY_SIZE];
typedef uint8_t sgx_aes_gcm_128bit_key_t[SGX_AESGCM_KEY_SIZE];
typedef uint8_t sgx_aes_gcm_128bit_tag_t[SGX_AESGCM_MAC_SIZE];


// AES CTR
sgx_status_t sgx_aes_ctr_encrypt(const sgx_aes_ctr_128bit_key_t *p_key,
                                const uint8_t *p_src, const uint32_t src_len,
                                uint8_t *p_ctr, const uint32_t ctr_inc_bits,
                                uint8_t *p_dst);

sgx_status_t sgx_aes_ctr_decrypt(const sgx_aes_ctr_128bit_key_t *p_key,
                                const uint8_t *p_src, const uint32_t src_len,
                                uint8_t *p_ctr, const uint32_t ctr_inc_bits,
                                uint8_t *p_dst);

// AES GCM
sgx_status_t sgx_rijndael128GCM_encrypt(const sgx_aes_gcm_128bit_key_t *p_key,
                                const uint8_t *p_src, uint32_t src_len, uint8_t *p_dst,
                                const uint8_t *p_iv, uint32_t iv_len,
                                const uint8_t *p_aad, uint32_t aad_len,
                                sgx_aes_gcm_128bit_tag_t *p_out_mac);

sgx_status_t sgx_rijndael128GCM_decrypt(const sgx_aes_gcm_128bit_key_t *p_key,
                                const uint8_t *p_src, uint32_t src_len, uint8_t *p_dst,
                                const uint8_t *p_iv, uint32_t iv_len,
                                const uint8_t *p_aad, uint32_t aad_len,
                                const sgx_aes_gcm_128bit_tag_t *p_in_mac);


#endif
