#ifndef __ENCRYPTION_HPP__
#define __ENCRYPTION_HPP__

#include "sgx_tcrypto.h"
#include <string>


class AES_CTR_context {
  public:
    sgx_aes_ctr_128bit_key_t *p_key;
    uint8_t *p_ctr;

    AES_CTR_context();
    explicit AES_CTR_context(uint8_t *key, uint8_t *ctr0);
    ~AES_CTR_context();


    size_t dump(const size_t offset, char *buffer);

    size_t encrypt(const uint8_t *p_src, const uint32_t src_len, uint8_t *p_dst);
    size_t decrypt(const uint8_t *p_src, const uint32_t src_len, uint8_t *p_dst);


    static int size();
};

#endif /*__ENCRYPTION_HPP__*/
