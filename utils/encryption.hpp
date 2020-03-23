#ifndef __ENCRYPTION_HPP__
#define __ENCRYPTION_HPP__

#include "sgx_tcrypto.h"
#include <string>


class AES_CTR_context {
  public:
    sgx_aes_ctr_128bit_key_t *p_key;
    uint8_t *p_ctr;

    AES_CTR_context();
    explicit AES_CTR_context(uint8_t *buffer);
    ~AES_CTR_context();


    size_t dump(const size_t offset, char *buffer);

    size_t encrypt(const uint8_t *p_src, const uint32_t src_len, uint8_t *p_dst);
    size_t decrypt(const uint8_t *p_src, const uint32_t src_len, uint8_t *p_dst);


    static size_t dump_size();
};

class AES_GCM_context {
  public:
    sgx_aes_gcm_128bit_key_t *p_key;
    uint8_t *p_iv;
    sgx_aes_gcm_128bit_tag_t *p_mac;

    AES_GCM_context();
    explicit AES_GCM_context(uint8_t *buffer);
    ~AES_GCM_context();


    size_t dump(const size_t offset, char *buffer);

    size_t encrypt(const uint8_t *p_src, const uint32_t src_len,
                    const uint8_t *p_aad, const uint32_t add_len, uint8_t *p_dst);
    size_t decrypt(const uint8_t *p_src, const uint32_t src_len,
                    const uint8_t *p_aad, const uint32_t add_len, uint8_t *p_dst);


    static size_t dump_size();
    static size_t dump_size_no_auth();
};


#endif /*__ENCRYPTION_HPP__*/
