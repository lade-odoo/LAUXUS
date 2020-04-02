#ifndef __FILENODE_HPP__
#define __FILENODE_HPP__

#include "../../utils/encryption.hpp"
#include "../../utils/metadata/node.hpp"
#include "../../utils/users/user.hpp"
#include <string>
#include <map>
#include <vector>



class Filenode: public Node {
  public:
    static const unsigned char OWNER_POLICY = 8;
    static const unsigned char READ_POLICY = 4;
    static const unsigned char WRITE_POLICY = 2;
    static const unsigned char EXEC_POLICY = 1;

    Filenode(const std::string &filename, AES_GCM_context *root_key, size_t block_size);
    ~Filenode();

    bool is_user_allowed(const unsigned char policy, User *user);
    int edit_user_policy(const unsigned char required_policy, User *user);

    size_t size();
    int getattr(User *user);
    int read(const long offset, const size_t buffer_size, char *buffer);
    int write(const long offset, const size_t data_size, const char *data);

    int load_encryption(const long offset, const size_t buffer_size, const char *buffer);
    int encryption_size(const long up_offset, const size_t up_size);
    int dump_encryption(const long up_offset, const size_t up_size, const size_t buffer_size, char *buffer);

  private:
    size_t block_size;
    std::map<User*, unsigned char> *allowed_users;
    std::vector<std::vector<char>*> *plain, *cipher;
    std::vector<AES_CTR_context*> *aes_ctr_ctxs;

    int encrypt_block(const size_t block_index);
    int decrypt_block(const size_t block_index);

  protected:
    size_t size_sensitive();
    int dump_sensitive(const size_t buffer_size, char *buffer);
    int load_sensitive(Node *parent, const size_t buffer_size, const char *buffer);
};

#endif /*__FILENODE_HPP__*/
