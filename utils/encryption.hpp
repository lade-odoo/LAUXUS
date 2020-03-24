#ifndef __ENCRYPTION_HPP__
#define __ENCRYPTION_HPP__

#include "sgx_tcrypto.h"
#include <string>


class AES_CTR_context {
  public:
    sgx_aes_ctr_128bit_key_t *p_key;
    uint8_t *p_ctr;

    AES_CTR_context();
    ~AES_CTR_context();


    int dump(char *buffer);
    int load(const char *buffer);

    int encrypt(const uint8_t *p_plain, const uint32_t plain_len, uint8_t *p_cypher);
    int decrypt(const uint8_t *p_cypher, const uint32_t cypher_len, uint8_t *p_plain);


    static size_t size();
};

class AES_GCM_context {
  public:
    sgx_aes_gcm_128bit_key_t *p_key;
    uint8_t *p_iv;
    sgx_aes_gcm_128bit_tag_t *p_mac;

    AES_GCM_context();
    ~AES_GCM_context();


    int dump(char *buffer);
    int encrypt_key_and_dump(AES_GCM_context *root_key, char *buffer);
    int dump_aad(char *buffer);
    int load(const char *buffer);
    int decrypt_key_and_load(AES_GCM_context *root_key, const char* buffer);

    int encrypt(const uint8_t *p_plain, const uint32_t plain_len,
                    const uint8_t *p_aad, const uint32_t aad_len, uint8_t *p_cypher);
    int decrypt(const uint8_t *p_cypher, const uint32_t cypher_len,
                    const uint8_t *p_aad, const uint32_t aad_len, uint8_t *p_plain);


    static size_t size();
    static size_t size_aad();
};


#endif /*__ENCRYPTION_HPP__*/
