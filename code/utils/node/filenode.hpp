#ifndef __FILENODE_HPP__
#define __FILENODE_HPP__

#include "../encryption/aes_gcm.hpp"
#include "node.hpp"
#include "filenode_content.hpp"
#include "../users/user.hpp"

#include <string>
#include <map>
#include <vector>



class Filenode: public Node {
  public:
    static const unsigned char OWNER_POLICY = 8;
    static const unsigned char READ_POLICY = 4;
    static const unsigned char WRITE_POLICY = 2;
    static const unsigned char EXEC_POLICY = 1;

    Filenode(const std::string &uuid, const std::string &filename, AES_GCM_context *root_key, size_t block_size);
    Filenode(const std::string &uuid, AES_GCM_context *root_key, size_t block_size);
    ~Filenode();

    bool equals(Filenode *other);

    bool is_user_allowed(const unsigned char policy, User *user);
    int edit_user_policy(const unsigned char required_policy, User *user);
    int getattr(User *user);

    size_t file_size();
    int read(const long offset, const size_t buffer_size, char *buffer);
    int write(const long offset, const size_t data_size, const char *data);

    int e_content_size(const long up_offset, const size_t up_size);
    int e_dump_content(const long up_offset, const size_t up_size, const size_t buffer_size, char *buffer);
    int e_load_content(const long offset, const size_t buffer_size, const char *buffer);

  private:
    FilenodeContent *content;
    std::map<int, unsigned char> *allowed_users;
    std::vector<AES_CTR_context*> *aes_ctr_ctxs;

    int encrypt_block(const size_t block_index);
    int decrypt_block(const size_t block_index);

  protected:
    size_t p_sensitive_size();
    int p_dump_sensitive(const size_t buffer_size, char *buffer);
    int p_load_sensitive(const size_t buffer_size, const char *buffer);
};

#endif /*__FILENODE_HPP__*/
