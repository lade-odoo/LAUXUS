#ifndef __SERIALIZATION_HPP__
#define __SERIALIZATION_HPP__

#include <string>


void dump(const std::string &dumppath, const size_t size, const char *buffer);
void dump_with_offset(const std::string &dumppath, const long offset, const size_t size, const char *buffer);

int delete_file(const std::string &path);


#endif /*__SERIALIZATION_HPP__*/
