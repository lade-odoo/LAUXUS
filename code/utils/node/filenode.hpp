#ifndef __FILENODE_HPP__
#define __FILENODE_HPP__

#include "../encryption/aes_gcm.hpp"
#include "node.hpp"
#include "filenode_content.hpp"

#include <string>
#include <map>
#include <vector>



class Filenode: public Node {
  public:
    Filenode(Node *parent, const std::string &uuid, const std::string &relative_path, AES_GCM_context *root_key, size_t block_size);
    Filenode(Node *parent, const std::string &uuid, AES_GCM_context *root_key, size_t block_size);
    ~Filenode();

    bool equals(Filenode *other);

    size_t file_size();
    int read(const long offset, const size_t buffer_size, char *buffer);
    int write(const long offset, const size_t data_size, const char *data);

    int e_content_size(const long up_offset, const size_t up_size);
    int e_dump_content(const long up_offset, const size_t up_size, const size_t buffer_size, char *buffer);
    int e_load_content(const long offset, const size_t buffer_size, const char *buffer);

  private:
    FilenodeContent *content;
    std::vector<AES_CTR_context*> *aes_ctr_ctxs;

    int encrypt_block(const size_t block_index);
    int decrypt_block(const size_t block_index);

  protected:
    size_t p_sensitive_size();
    int p_dump_sensitive(const size_t buffer_size, char *buffer);
    int p_load_sensitive(const size_t buffer_size, const char *buffer);

    bool is_correct_node(string parent_path);
    Node* retrieve_node(string relative_path);
};

#endif /*__FILENODE_HPP__*/