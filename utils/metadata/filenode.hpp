#ifndef __FILENODE_HPP__
#define __FILENODE_HPP__

#include "../../utils/encryption.hpp"
#include "../../utils/metadata/node.hpp"
#include <string>
#include <vector>



class Filenode: public Node {
  public:
    Filenode(const std::string &filename, size_t block_size);
    ~Filenode();

    size_t size();
    int read(const long offset, const size_t buffer_size, char *buffer);
    int write(const long offset, const size_t data_size, const char *data);

    size_t metadata_size();

    int load_encryption(const long offset, const size_t buffer_size, const char *buffer);
    int encryption_size(const long up_offset, const size_t up_size);
    int dump_encryption(const long up_offset, const size_t up_size, const size_t buffer_size, char *buffer);

  private:
    size_t block_size;
    std::vector<std::vector<char>*> *plain, *cipher;
    std::vector<AES_CTR_context*> *aes_ctr_ctxs;

    int encrypt_block(const size_t block_index);
    int decrypt_block(const size_t block_index);

  protected:
    size_t size_sensitive();
    int dump_sensitive(char *buffer);
    int load_sensitive(const size_t buffer_size, const char *buffer);

    size_t size_aad();
    int dump_aad(char *buffer);
};

#endif /*__FILENODE_HPP__*/
