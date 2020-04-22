#ifndef __MISC_HPP__
#define __MISC_HPP__

#include <string>
#include <vector>

using namespace std;


vector<string> tokenize(const size_t buffer_size, const char *entries, const char separator);

string get_directory(const string &filepath);
string get_relative_path(const string &filepath);
string get_parent_path(const string &path);
string get_child_path(const string &path);
string clean_path(const string &path);

int create_directory(const string &dirpath);


#endif /*__MISC_HPP__*/
