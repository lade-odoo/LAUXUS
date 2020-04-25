#ifndef __FILESYSTEM_HPP__
#define __FILESYSTEM_HPP__

#include "../encryption/aes_gcm.hpp"
#include "../users/user.hpp"
#include "../node/filenode.hpp"
#include "../node/supernode.hpp"

#include <string>
#include <vector>

using namespace std;


/**
 * An in-memory file system
 */
class FileSystem {
  public:
    static const size_t DEFAULT_BLOCK_SIZE = 4096;
    AES_GCM_context *root_key, *audit_root_key;
    Supernode *supernode;
    User *current_user;

    FileSystem(AES_GCM_context *root_key, AES_GCM_context *audit_root_key, Supernode *supernode, size_t block_size);
    FileSystem(AES_GCM_context *root_key, AES_GCM_context *audit_root_key, size_t block_size);
    ~FileSystem();
    void init_dumping_folders(const string &CONTENT_DIR, const string &META_DIR, const string &AUDIT_DIR);
    void link_supernode(Supernode *node);

    Node* retrieve_node(const string &path);
    Node* _retrieve_node(Node *parent, const string &path);
    int edit_user_entitlement(const string &path, const unsigned char rights, const string user_uuid);

    int get_rights(const string &path);
    int entry_type(const string &path);

    int file_size(const string &filepath);
    int create_file(const string &reason, const string &filepath);
    int read_file(const string &reason, const string &filepath, const long offset, const size_t buffer_size, char *buffer);
    int write_file(const string &reason, const string &filepath, const long offset, const size_t data_size, const char *data);
    int unlink(const string &reason, const string &filepath);

    vector<string> readdir(const string &path);
    int create_directory(const string &reason, const string &dirpath);
    int rm_directory(const string &reason, const string &dirpath);

    int e_write_meta_to_disk(Node *node);

    // Static functioncs
    static string get_directory_path(const string &filepath);
    static string get_relative_path(const string &filepath);
    static string get_parent_path(const string &path);
    static string get_child_path(const string &path);
    static string clean_path(const string &path);

  private:
    string CONTENT_DIR, META_DIR, AUDIT_DIR;
    size_t block_size;

    Node* load_metadata(string uuid);
    int load_content(Filenode *node, const long offset, const size_t length);

    int e_write_file_to_disk(Filenode *node, const long up_offset, const size_t up_size);
    int e_append_audit_to_disk(Node *node, const string &reason);

    int e_load_meta_from_disk(const string &uuid, char **buffer);
    int e_load_fileblocks_from_disk(const string &uuid, const size_t start_block, const size_t end_block, char **buffer);

    int delete_from_disk(Node *node, const string &from_dir);

    int _return_and_free(int rt, const vector<Node*> &nodes);
};

struct NodeDeleter {
  void operator()(Node* node) const {
    if (node->node_type != Node::SUPERNODE_TYPE)
      delete node;
  }
};

#endif /*__FILESYSTEM_HPP__*/