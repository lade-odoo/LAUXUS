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


    size_t dump(char *buffer);

    int encrypt(const uint8_t *p_plain, const uint32_t plain_len, uint8_t *p_cypher);
    int decrypt(const uint8_t *p_cypher, const uint32_t cypher_len, uint8_t *p_plain);


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


    size_t dump(char *buffer);

    int encrypt(const uint8_t *p_plain, const uint32_t plain_len,
                    const uint8_t *p_aad, const uint32_t aad_len, uint8_t *p_cypher);
    int decrypt(const uint8_t *p_cypher, const uint32_t cypher_len,
                    const uint8_t *p_aad, const uint32_t aad_len, uint8_t *p_plain);


    static size_t dump_size();
    static size_t dump_size_no_auth();
};


#endif /*__ENCRYPTION_HPP__*/
