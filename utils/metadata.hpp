#ifndef __METADATA_HPP__
#define __METADATA_HPP__

#include "sgx_tcrypto.h"
#include <string>
#include <vector>


class AES_CTR_context {
  public:
    sgx_aes_ctr_128bit_key_t *p_key;
    uint8_t *p_ctr;

    AES_CTR_context();
    ~AES_CTR_context();
};


class Filenode {
  public:
    std::string filename;

    Filenode(const std::string &filename, size_t block_size);
    ~Filenode();

    size_t size();
    size_t read(const long offset, const size_t buffer_size, char *buffer);
    size_t write(const long offset, const size_t data_size, const char *data);

    size_t metadata_size();
    size_t dump_metadata(const size_t buffer_size, char *buffer);

  private:
    size_t block_size;
    std::vector<std::vector<char>*> *plain, *cipher;
    std::vector<AES_CTR_context*> *aes_ctr_ctxs;

    size_t encrypt_block(const size_t block_index);
};

#endif /*__METADATA_HPP__*/
