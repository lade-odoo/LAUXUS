#ifndef __FILESYSTEM_HPP__
#define __FILESYSTEM_HPP__

#include "../../../flag.h"
#if EMULATING
#   include "../../../tests/SGX_Emulator/sgx_error.hpp"
#   include "../../../tests/SGX_Emulator/Enclave_t.hpp"
#else
#   include "sgx_error.h"
#   include "../../../Enclave/Enclave_t.h"
#endif

#include "user.hpp"
#include "misc.hpp"
#include "nodes/node.hpp"
#include "nodes/dirnode.hpp"
#include "nodes/filenode.hpp"
#include "nodes/supernode.hpp"
#include "nodes/node_audit.hpp"
#include "nodes/filenode_content.hpp"
#include "encryption/aes_gcm.hpp"

#include <string>
#include <cstring>
#include <vector>
#include <cerrno>
#include <memory>

using namespace std;


#define DEFAULT_BLOCK_SIZE    4096


class FileSystem {
  public:
    lauxus_gcm_t *root_key, *audit_root_key;
    Supernode *supernode;
    User *current_user;

    FileSystem(lauxus_gcm_t *root_key, lauxus_gcm_t *audit_root_key, Supernode *supernode,
            const string &CONTENT_DIR, const string &META_DIR, const string &AUDIT_DIR, size_t block_size);
    ~FileSystem();

    int edit_user_entitlement(const string &path, lauxus_right_t rights, const lauxus_uuid_t *u_uuid);
    int get_rights(const string &path, lauxus_right_t *rights);

    int entry_type(const string &path);
    int get_times(const string &path, time_t *atime, time_t *mtime, time_t *ctime);
    int rename(const string &old_path, const string &new_path);

    int file_size(const string &filepath);
    int open_file(const string &filepath, const lauxus_right_t asked_rights);
    int close_file(const string &filepath);
    int create_file(const string &reason, const string &filepath);
    int read_file(const string &reason, const string &filepath, const long offset, const size_t buffer_size, uint8_t *buffer);
    int write_file(const string &reason, const string &filepath, const long offset, const size_t data_size, const uint8_t *data);
    int truncate_file(const string &filepath, const long new_size);
    int unlink(const string &reason, const string &filepath);

    int open_directory(const string &dirpath, const int asked_rights);
    vector<string> readdir(const string &path);
    int create_directory(const string &reason, const string &dirpath);
    int rm_directory(const string &reason, const string &dirpath);


    int e_write_meta_to_disk(Node *node, bool trunc=false);

  private:
    map<string, Node*> *loaded_node;
    string CONTENT_DIR, META_DIR, AUDIT_DIR;
    size_t block_size;

    Node* retrieve_node(const string &path);
    Node* _retrieve_node(Node *parent, const string &path);
    void free_node(const string &path);
    void delete_node(Node *node);

    // loading metadata
    Node* load_metadata(const lauxus_uuid_t *n_uuid);
    int e_load_meta_from_disk(const lauxus_uuid_t *uuid, uint8_t **buffer);

    // loading filenode content
    int load_content(Filenode *node, const long offset, const size_t length);
    int e_load_fileblocks_from_disk(const lauxus_uuid_t *n_uuid, const size_t start_block, const size_t end_block, uint8_t **buffer);

    // writing to file and appending
    int e_write_file_to_disk(Filenode *node, const long up_offset, const size_t up_size);
    int e_truncate_file_to_disk(Filenode *node, const long new_size);
    int e_append_audit_to_disk(Node *node, const string &reason);

    // deleting from disk
    int delete_from_disk(Node *node, const string &from_dir);
};

#endif /*__FILESYSTEM_HPP__*/
