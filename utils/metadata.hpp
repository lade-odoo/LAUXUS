#ifndef __METADATA_HPP__
#define __METADATA_HPP__

#include "../utils/encryption.hpp"
#include <string>
#include <vector>


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
    size_t load_metadata(const size_t buffer_size, const char *buffer);

    size_t encryption_size(const long up_offset, const size_t up_size);
    size_t dump_encryption(const long up_offset, const size_t up_size, const size_t buffer_size, char *buffer);
    size_t load_encryption(const long offset, const size_t buffer_size, const char *buffer);

  private:
    size_t block_size;
    std::vector<std::vector<char>*> *plain, *cipher;
    std::vector<AES_CTR_context*> *aes_ctr_ctxs;
    AES_GCM_context *aes_gcm_ctx;

    size_t encrypt_block(const size_t block_index);
    size_t decrypt_block(const size_t block_index);
};

#endif /*__METADATA_HPP__*/
