#ifndef __NODE_HPP__
#define __NODE_HPP__

#include "../../../../flag.h"
#if EMULATING
#   include "../../../../tests/SGX_Emulator/sgx_trts.hpp"
// #   include "../../../../tests/SGX_Emulator/Enclave_t.hpp"
#else
#   include "sgx_trts.h"
#   include "../../../../Enclave/Enclave_t.h"
#endif

#include "../user.hpp"
#include "../encryption/aes_gcm.hpp"
#include "../encryption/metadata.hpp"
#include "../../../../utils/headers/rights.hpp"

#include <time.h>
#include <string>
#include <cstring>
#include <map>

using namespace std;


typedef enum {
  LAUXUS_SUPERNODE,
  LAUXUS_DIRNODE,
  LAUXUS_FILENODE,
  LAUXUS_EMPTYNODE
} lauxus_node_type;


class Node: public Metadata {
  public:
    lauxus_node_type type = LAUXUS_EMPTYNODE;
    lauxus_uuid_t *n_uuid;
    string relative_path;
    time_t atime, mtime, ctime;
    map<string, lauxus_uuid_t*> *node_entries; // mapping relative_path - uuid

    Node(const string &relative_path, lauxus_gcm_t *root_key);
    Node(lauxus_gcm_t *root_key);
    ~Node();

    bool equals(Node *other);
    string absolute_path();

    int add_node_entry(string relative_path, lauxus_uuid_t *uuid);
    int remove_node_entry(string relative_path);

    bool has_user_rights(const lauxus_right_t min_rights, User *user);
    int edit_user_rights(const lauxus_right_t right, User *user);
    int remove_user_rights(User *user);
    lauxus_right_t get_rights(User *user);

    int update_atime();
    int update_mtime();
    int update_ctime();


  private:
    map<string, lauxus_right_t> *entitlements; // mapping user_uuid - rights

    int update_time(time_t *time);


  protected:
    size_t p_preamble_size();
    int p_dump_preamble(const size_t buffer_size, uint8_t *buffer);
    int p_load_preamble(const size_t buffer_size, const uint8_t *buffer);

    size_t p_sensitive_size();
    int p_dump_sensitive(const size_t buffer_size, uint8_t *buffer);
    int p_load_sensitive(const size_t buffer_size, const uint8_t *buffer);
};

#endif /*__NODE_HPP__*/
