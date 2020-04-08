#ifndef __FILESYSTEM_HPP__
#define __FILESYSTEM_HPP__

#include <string>
#include <map>
#include <vector>

#include "../utils/encryption.hpp"
#include "../utils/users/user.hpp"
#include "../utils/metadata/filenode.hpp"
#include "../utils/metadata/supernode.hpp"


/**
 * An in-memory file system
 */
class FileSystem {
  public:
    static const size_t DEFAULT_BLOCK_SIZE = 4096;
    AES_GCM_context *root_key;
    Supernode *supernode;
    User *current_user;

    FileSystem(AES_GCM_context *root_key, Supernode *supernode, size_t block_size);

    int edit_user_policy(const std::string &filename, const unsigned char policy, const int user_id);

    std::vector<std::string> readdir();

    int get_uuid(const std::string &filename, const size_t buffer_size, char *buffer);
    bool isfile(const std::string &filename);
    int file_size(const std::string &filename);
    int getattr(const std::string &filename);
    int create_file(const std::string &filename);
    int read_file(const std::string &filename, const long offset, const size_t buffer_size, char *buffer);
    int write_file(const std::string &filename, const long offset, const size_t data_size, const char *data);
    int unlink(const std::string &filename);

    int e_metadata_size(const std::string &filename);
    int e_dump_metadata(const std::string &filename, const size_t buffer_size, char *buffer);
    int e_load_metadata(const std::string &uuid, const size_t buffer_size, const char *buffer);

    int e_file_size(const std::string &filename, const long up_offset, const size_t up_size);
    int e_dump_file(const std::string &filename, const long up_offset, const size_t up_size, const size_t buffer_size, char *buffer);
    int e_load_file(const std::string &uuid, const long offset, const size_t buffer_size, const char *buffer);

  private:
    size_t block_size;

    std::map<std::string, Filenode*> *files;


    Filenode* retrieve_node(const std::string &filename);
    Filenode* retrieve_node_with_uuid(const std::string &uuid);
};

#endif /*__FILESYSTEM_HPP__*/
