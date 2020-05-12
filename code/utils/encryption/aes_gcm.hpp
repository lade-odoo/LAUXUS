#ifndef __AES_GCM_CONTEXT_HPP__
#define __AES_GCM_CONTEXT_HPP__

#include "../../flag.h"
#if EMULATING
#  include "../../tests/SGX_Emulator/sgx_tcrypto.hpp"
#else
#   include "sgx_tcrypto.h"
#endif

#include <string>


class AES_GCM_context {
  public:
    sgx_aes_gcm_128bit_key_t *p_key;
    uint8_t *p_iv;
    sgx_aes_gcm_128bit_tag_t *p_mac;

    AES_GCM_context();
    ~AES_GCM_context();

    void update_iv();

    int dump(const size_t buffer_size, char *buffer);
    int dump_without_mac(const size_t buffer_size, char *buffer);
    int load(const size_t buffer_size, const char *buffer);
    int load_without_mac(const size_t buffer_size, const char *buffer);

    bool equals(AES_GCM_context *other);

    int encrypt(const uint8_t *p_plain, const uint32_t plain_len,
                    const uint8_t *p_aad, const uint32_t aad_len, uint8_t *p_cypher);
    int decrypt(const uint8_t *p_cypher, const uint32_t cypher_len,
                    const uint8_t *p_aad, const uint32_t aad_len, uint8_t *p_plain);
    int decrypt_with_mac(const uint8_t *p_cypher, const uint32_t cypher_len,
                    const uint8_t *p_aad, const uint32_t aad_len, uint8_t *p_plain,
                    const sgx_aes_gcm_128bit_tag_t *mac);


    static size_t size();
    static size_t size_without_mac();
};


#endif /*__AES_GCM_CONTEXT_HPP__*/
