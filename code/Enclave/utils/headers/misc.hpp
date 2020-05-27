#ifndef _MISC_HPP_
#define _MISC_HPP_

#include <string>
#include <cstring>

using namespace std;


string get_directory_path(const string &filepath);
string get_relative_path(const string &filepath);
string get_parent_path(const string &path);
string get_child_path(const string &path);
string clean_path(const string &path);


#endif /*_MISC_HPP_*/
