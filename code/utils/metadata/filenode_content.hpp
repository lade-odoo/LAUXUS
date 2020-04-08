#ifndef __FILENODE_CONTENT_HPP__
#define __FILENODE_CONTENT_HPP__

#include "../../utils/encryption.hpp"

#include <string>
#include <vector>



class FilenodeContent {
  public:
    FilenodeContent(size_t block_size, std::vector<AES_CTR_context*> *aes_ctr_ctxs);
    ~FilenodeContent();

    bool equals(FilenodeContent *other);

    size_t size();
    int read(const long offset, const size_t buffer_size, char *buffer);
    int write(const long offset, const size_t data_size, const char *data);

    int e_size(const long up_offset, const size_t up_size);
    int e_dump(const long up_offset, const size_t up_size, const size_t buffer_size, char *buffer);
    int e_load(const long offset, const size_t buffer_size, const char *buffer);

  private:
    size_t block_size;
    std::vector<std::vector<char>*> *plain, *cipher;
    std::vector<AES_CTR_context*> *aes_ctr_ctxs;

    int encrypt_block(const size_t block_index);
    int decrypt_block(const size_t block_index);
};

#endif /*__FILENODE_CONTENT_HPP__*/
