#ifndef __SUPERNODE_HPP__
#define __SUPERNODE_HPP__

#include "node.hpp"
#include "../uuid.hpp"
#include "../user.hpp"
#include "../encryption/aes_gcm.hpp"

#include <string>
#include <cstring>
#include <map>

using namespace std;

class Supernode: public Node {
  public:
    map<string, User*> *allowed_users;
    Supernode(lauxus_gcm_t *root_key);
    ~Supernode();

    bool equals(Supernode *other);

    User *add_user(User *user);
    User *remove_user_from_uuid(const lauxus_uuid_t *u_uuid);
    User *check_user(User *user);
    User *retrieve_user(const lauxus_uuid_t *u_uuid);

  // private:

  protected:
    size_t p_sensitive_size();
    int p_dump_sensitive(const size_t buffer_size, uint8_t *buffer);
    int p_load_sensitive(const size_t buffer_size, const uint8_t *buffer);
};

#endif /*__SUPERNODE_HPP__*/
