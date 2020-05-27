#ifndef _SGX_TCRYPTO_H_
#define _SGX_TCRYPTO_H_

#include "sgx_error.hpp"
#include <stdint.h>


#define SGX_AESCTR_KEY_SIZE             16
#define SGX_AESGCM_KEY_SIZE             16
#define SGX_AESGCM_MAC_SIZE             16
#define SGX_ECP256_KEY_SIZE             32
#define SGX_NISTP_ECP256_KEY_SIZE       (SGX_ECP256_KEY_SIZE/sizeof(uint32_t))


typedef uint8_t sgx_aes_ctr_128bit_key_t[SGX_AESCTR_KEY_SIZE];
typedef uint8_t sgx_aes_gcm_128bit_key_t[SGX_AESGCM_KEY_SIZE];
typedef uint8_t sgx_aes_gcm_128bit_tag_t[SGX_AESGCM_MAC_SIZE];
typedef void* sgx_ecc_state_handle_t;
typedef struct _sgx_ec256_private_t {
    uint8_t r[SGX_ECP256_KEY_SIZE];
} sgx_ec256_private_t;
typedef struct _sgx_ec256_public_t {
    uint8_t gx[SGX_ECP256_KEY_SIZE];
    uint8_t gy[SGX_ECP256_KEY_SIZE];
} sgx_ec256_public_t;
typedef struct _sgx_ec256_signature_t {
    uint32_t x[SGX_NISTP_ECP256_KEY_SIZE];
    uint32_t y[SGX_NISTP_ECP256_KEY_SIZE];
} sgx_ec256_signature_t;

typedef enum {
    SGX_EC_VALID,
    SGX_EC_INVALID_SIGNATURE
} sgx_generic_ecresult_t;


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

// ECC 256
sgx_status_t sgx_ecc256_open_context(sgx_ecc_state_handle_t* p_ecc_handle);

sgx_status_t sgx_ecc256_close_context(sgx_ecc_state_handle_t ecc_handle);

sgx_status_t sgx_ecc256_create_key_pair(sgx_ec256_private_t *p_private, sgx_ec256_public_t *p_public,
                                        sgx_ecc_state_handle_t ecc_handle);

sgx_status_t sgx_ecdsa_sign(const uint8_t *p_data, uint32_t data_size,
                            sgx_ec256_private_t *p_private, sgx_ec256_signature_t *p_signature,
                            sgx_ecc_state_handle_t ecc_handle);

sgx_status_t sgx_ecdsa_verify(const uint8_t *p_data, uint32_t data_size,
                            const sgx_ec256_public_t *p_public, sgx_ec256_signature_t *p_signature,
                            uint8_t *p_result, sgx_ecc_state_handle_t ecc_handle);


#endif
