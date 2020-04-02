#ifndef __MISC_HPP__
#define __MISC_HPP__

#include <string>
#include <vector>


std::vector<std::string> tokenize(const size_t buffer_size, const char *entries, const char separator);

std::string get_directory(const std::string &filepath);
std::string get_filename(const std::string &filepath);


#endif /*__MISC_HPP__*/
