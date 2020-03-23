#ifndef __SERIALIZATION_HPP__
#define __SERIALIZATION_HPP__

#include <string>
#include <vector>


int dump(const std::string &dumppath, const size_t size, const char *buffer);
int dump_with_offset(const std::string &dumppath, const long offset, const size_t size, const char *buffer);

int load(const std::string &loadpath, char **buffer);
int load_with_offset(const std::string &loadpath, const long offset, const size_t size, char **buffer);

bool delete_file(const std::string &path);


std::vector<std::string> read_directory(const std::string& dirpath);


size_t file_size(const std::string &path);


#endif /*__SERIALIZATION_HPP__*/
