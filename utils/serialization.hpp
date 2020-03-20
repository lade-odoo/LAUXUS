#ifndef __SERIALIZATION_HPP__
#define __SERIALIZATION_HPP__

#include <string>


int dump(const std::string &dumppath, const size_t size, const char *buffer);

int delete_file(const std::string &path);


#endif /*__SERIALIZATION_HPP__*/
