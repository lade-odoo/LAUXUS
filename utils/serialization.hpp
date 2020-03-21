#ifndef __SERIALIZATION_HPP__
#define __SERIALIZATION_HPP__

#include <string>
#include <vector>


void dump(const std::string &dumppath, const size_t size, const char *buffer);
void dump_with_offset(const std::string &dumppath, const long offset, const size_t size, const char *buffer);

size_t load(const std::string &loadpath, char **buffer);
size_t load_with_offset(const std::string &loadpath, const long offset, const size_t size, char **buffer);


int delete_file(const std::string &path);


std::vector<std::string> read_directory(const std::string& dirpath);


#endif /*__SERIALIZATION_HPP__*/
