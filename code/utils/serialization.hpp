#ifndef __SERIALIZATION_HPP__
#define __SERIALIZATION_HPP__

#include <string>
#include <vector>

using namespace std;


int dump(const string &dumppath, const size_t size, const char *buffer);
int dump_with_offset(const string &dumppath, const long offset, const size_t size, const char *buffer);
int dump_append(const string &dumppath, const size_t size, const char *buffer);

int load(const string &loadpath, char *buffer);
int load_with_offset(const string &loadpath, const long offset, const size_t size, char *buffer);

bool delete_file(const string &path);


vector<string> read_directory(const string& dirpath);


size_t file_size(const string &path);


#endif /*__SERIALIZATION_HPP__*/
