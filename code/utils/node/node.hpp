#ifndef __NODE_HPP__
#define __NODE_HPP__

#include "../metadata.hpp"
#include "../users/user.hpp"
#include "../encryption/aes_gcm.hpp"

#include <string>
#include <map>

using namespace std;


class Node: public Metadata {
  public:
    static const size_t UUID_SIZE = 21;
    static const unsigned char OWNER_RIGHT = 8;
    static const unsigned char READ_RIGHT = 4;
    static const unsigned char WRITE_RIGHT = 2;
    static const unsigned char EXEC_RIGHT = 1;

    static const unsigned char SUPERNODE_TYPE = 0;
    static const unsigned char DIRNODE_TYPE = 1;
    static const unsigned char FILENODE_TYPE = 2;
    unsigned char node_type = -1;

    string relative_path, uuid;
    map<string, string> *node_entries; // mapping relative_path - uuid

    Node(const string &uuid, const string &relative_path, AES_GCM_context *root_key);
    Node(const string &uuid, AES_GCM_context *root_key);
    ~Node();

    bool equals(Node *other);
    string absolute_path();

    int add_node_entry(string relative_path, string uuid);
    int remove_node_entry(string relative_path);

    bool has_user_rights(const unsigned char min_rights, User *user);
    int edit_user_entitlement(const unsigned char rights, User *user);
    int remove_user_entitlement(User *user);
    int get_rights(User *user);

    // Static functions
    static string generate_uuid();


  private:
    map<string, unsigned char> *entitlements; // mapping user_uuid - rights ORWX


  protected:
    size_t p_preamble_size();
    int p_dump_preamble(const size_t buffer_size, char *buffer);
    int p_load_preamble(const size_t buffer_size, const char *buffer);

    size_t p_sensitive_size();
    int p_dump_sensitive(const size_t buffer_size, char *buffer);
    int p_load_sensitive(const size_t buffer_size, const char *buffer);
};

#endif /*__NODE_HPP__*/
