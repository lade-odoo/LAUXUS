#ifndef _SGX_TSEAL_H_
#define _SGX_TSEAL_H_

#include <stddef.h>
#include <stdint.h>
#include "sgx_error.hpp"
#include "sgx_utils.hpp"
#include "sgx_tcrypto.hpp"

#define SGX_SEAL_TAG_SIZE       16
#define SGX_SEAL_IV_SIZE        12

typedef struct _aes_gcm_data_t {
    uint32_t  payload_size;
    uint8_t   reserved[12];
    uint8_t   payload_tag[SGX_SEAL_TAG_SIZE];
    uint8_t   payload[];
} sgx_aes_gcm_data_t;

typedef struct _sealed_data_t {
    uint8_t  key_request[64];
    uint32_t           plain_text_offset;
    uint8_t            reserved[12];
    sgx_aes_gcm_data_t aes_data;
} sgx_sealed_data_t;


sgx_status_t sgx_seal_data(const uint32_t additional_MACtext_length,
    const uint8_t *p_additional_MACtext,
    const uint32_t text2encrypt_length,
    const uint8_t *p_text2encrypt,
    const uint32_t sealed_data_size,
    sgx_sealed_data_t *p_sealed_data);

sgx_status_t sgx_unseal_data(const sgx_sealed_data_t *p_sealed_data,
    uint8_t *p_additional_MACtext,
    uint32_t *p_additional_MACtext_length,
    uint8_t *p_decrypted_text,
    uint32_t *p_decrypted_text_length);

#endif
