#ifndef __METADATA_HPP__
#define __METADATA_HPP__

#include <string>
#include <vector>


class Filenode {
  public:
    std::string filename;

    Filenode(const std::string &filename, size_t block_size);
    ~Filenode();

    size_t size();
    size_t read(const long offset, const size_t buffer_size, char *buffer);
    size_t write(const long offset, const size_t data_size, const char *data);

    size_t metadata_size();
    size_t dump_metadata(const size_t buffer_size, char *buffer);

  private:
    size_t block_size;
    std::vector<std::vector<char>*> *blocks;
};

#endif /*__METADATA_HPP__*/
