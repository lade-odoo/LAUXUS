#ifndef __AES_CTR_CONTEXT_HPP__
#define __AES_CTR_CONTEXT_HPP__

#include "../../flag.h"
#if EMULATING
#  include "../../tests/SGX_Emulator/sgx_tcrypto.hpp"
#else
#   include "sgx_tcrypto.h"
#endif

#include <string>


class AES_CTR_context {
  public:
    sgx_aes_ctr_128bit_key_t *p_key;
    uint8_t *p_ctr;

    AES_CTR_context();
    ~AES_CTR_context();


    int dump(const size_t buffer_size, char *buffer);
    int load(const size_t buffer_size, const char *buffer);

    bool equals(AES_CTR_context *other);

    int encrypt(const uint8_t *p_plain, const uint32_t plain_len, uint8_t *p_cypher);
    int decrypt(const uint8_t *p_cypher, const uint32_t cypher_len, uint8_t *p_plain);


    static size_t size();
};


#endif /*__AES_CTR_CONTEXT_HPP__*/
