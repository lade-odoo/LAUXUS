#ifndef __FILESYSTEM_HPP__
#define __FILESYSTEM_HPP__

#include <string>
#include <map>
#include <vector>

#include "../utils/metadata.hpp"


/**
 * An in-memory file system
 */
class FileSystem {
  public:
    static const size_t DEFAULT_BLOCK_SIZE = 4096;

    FileSystem(const char* mount_dir, size_t block_size);

    std::vector<std::string> readdir();

    bool isfile(const std::string &filename);
    size_t file_size(const std::string &filename);
    int create_file(const std::string &filename);
    int read_file(const std::string &filename, const long offset, const size_t buffer_size, char *buffer);
    int write_file(const std::string &filename, const long offset, const size_t data_size, const char *data);
    int unlink(const std::string &filename);

    int metadata_size(const std::string &filename);
    int dump_metadata(const std::string &filename, const size_t buffer_size, char *buffer);

  private:
    size_t block_size;
    const char* mount_dir;

    std::map<std::string, Filenode*> *files; // key = metapath


    Filenode* retrieve_node(const std::string &filename);
};

#endif /*__FILESYSTEM_HPP__*/
