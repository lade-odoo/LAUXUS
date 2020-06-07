#ifndef __SERIALISATION_HPP__
#define __SERIALISATION_HPP__

#include <vector>
#include <string>
#include <fstream>
#include <unistd.h>
#include <dirent.h>

using namespace std;


int load(string &path, size_t size, uint8_t *content);
int load_with_offset(string &path, long offset, size_t size, uint8_t *content);

int dump(string &path, size_t size, const uint8_t *content);
int dump_append(string &path, size_t size, const uint8_t *content);
int dump_with_offset(string &path, long offset, size_t size, const uint8_t *content);
int truncate_file(string &path, const long new_size);

int file_size(string &path);


int create_directory(string &path);
vector<string> read_directory(const string& dirpath);


#endif /*__SERIALISATION_HPP__*/
