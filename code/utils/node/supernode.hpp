#ifndef __SUPERNODE_HPP__
#define __SUPERNODE_HPP__

#include "../users/user.hpp"
#include "../encryption/aes_gcm.hpp"
#include "node.hpp"

#include <string>
#include <map>

using namespace std;



class Supernode: public Node {
  public:
    Supernode(const string &filename, AES_GCM_context *root_key);
    ~Supernode();

    bool equals(Supernode *other);

    User *add_user(User *user);
    User *remove_user_from_id(int user_id);
    User *check_user(User *user);
    User *retrieve_user(int user_id);

  private:
    map<int, User*> *allowed_users;

  protected:
    size_t p_sensitive_size();
    int p_dump_sensitive(const size_t buffer_size, char *buffer);
    int p_load_sensitive(const size_t buffer_size, const char *buffer);
};

#endif /*__SUPERNODE_HPP__*/
