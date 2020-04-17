#ifndef __MISC_HPP__
#define __MISC_HPP__

#include <string>
#include <vector>

using namespace std;


vector<string> tokenize(const size_t buffer_size, const char *entries, const char separator);

string get_directory(const string &filepath);
string get_filename(const string &filepath);
string clean_path(const string &path);

int create_directory(const string &dirpath);


#endif /*__MISC_HPP__*/
