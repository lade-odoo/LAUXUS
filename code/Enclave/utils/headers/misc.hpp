#ifndef _MISC_HPP_
#define _MISC_HPP_

#include <string>
#include <cstring>

using namespace std;


string sgx_get_directory_path(const string &filepath);
string sgx_get_relative_path(const string &filepath);
string sgx_get_parent_path(const string &path);
string sgx_get_child_path(const string &path);
string sgx_clean_path(const string &path);


#endif /*_MISC_HPP_*/
