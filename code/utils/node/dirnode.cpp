#include "dirnode.hpp"
#include "node.hpp"
#include "../users/user.hpp"
#include "../encryption/aes_gcm.hpp"

#include <string>

using namespace std;


Dirnode::Dirnode(const std::string &uuid, const std::string &relative_path, AES_GCM_context *root_key):Node::Node(uuid, relative_path, root_key) {
  this->node_type = Node::DIRNODE_TYPE;
}
Dirnode::Dirnode(const std::string &uuid, AES_GCM_context *root_key):Dirnode::Dirnode(uuid, "", root_key) {}
