#include "../../headers/nodes/dirnode.hpp"


Dirnode::Dirnode(const string &relative_path, lauxus_gcm_t *root_key):Node::Node(relative_path, root_key) {
  this->type = LAUXUS_DIRNODE;
}
Dirnode::Dirnode(lauxus_gcm_t *root_key):Dirnode::Dirnode("", root_key) {}
