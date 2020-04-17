#ifndef __FILESYSTEM_HPP__
#define __FILESYSTEM_HPP__

#include "../utils/encryption/aes_gcm.hpp"
#include "../utils/users/user.hpp"
#include "../utils/node/filenode.hpp"
#include "../utils/node/supernode.hpp"

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
    void init_dumping_folders(const string &CONTENT_DIR, const string &META_DIR, const string &AUDIT_DIR);

    int edit_user_entitlement(const string &path, const unsigned char rights, const int user_id);

    vector<string> readdir();
    int get_rights(const string &path);
    int entry_type(const string &path);

    int file_size(const string &filepath);
    int create_file(const string &reason, const string &filepath);
    int read_file(const string &reason, const string &filepath, const long offset, const size_t buffer_size, char *buffer);
    int write_file(const string &reason, const string &filepath, const long offset, const size_t data_size, const char *data);
    int unlink(const string &filepath);

  private:
    string CONTENT_DIR, META_DIR, AUDIT_DIR;
    size_t block_size;

    int load_metadata(Node *parent);
    int load_content(Node *parent);

    int e_write_meta_to_disk(Node *node);
    int e_write_file_to_disk(Filenode *node, const long up_offset, const size_t up_size);
    int e_append_audit_to_disk(Node *node, const string &reason);

    int e_load_meta_from_disk(const string &uuid, char **buffer);
    int e_load_file_from_disk(const string &uuid, const long offset, char **buffer);

    int delete_from_disk(Node *node, const string &from_dir);
};

#endif /*__FILESYSTEM_HPP__*/
