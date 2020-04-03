#include "../utils/serialization.hpp"

#include <string>
#include <vector>
#include <fstream>
#include <dirent.h>


using namespace std;



int dump(const string &dumppath, const size_t size, const char *buffer) {
  ofstream stream(dumppath, ios::out | ios::binary);
  if (stream.is_open()) {
    stream.write(buffer, size);
    stream.close();
    return size;
  }
  return -1;
}

int dump_with_offset(const string &dumppath, const long offset, const size_t size, const char *buffer) {
  ofstream stream(dumppath, ios::in | ios::out | ios::binary);
  if (stream.is_open() && (long)file_size(dumppath) >= offset) {
    stream.seekp(offset, ios::beg);
    stream.write(buffer, size);
    stream.close();
    return size;
  }
  return -1;
}

int load(const string &loadpath, char **buffer) {
  ifstream stream(loadpath, ios::binary);
  if (stream.is_open()) {
    size_t size = file_size(loadpath);
    *buffer = new char[size];
    stream.read(*buffer, size);
    stream.close();
    return size;
  }
  return -1;
}

int load_with_offset(const string &loadpath, const long offset, const size_t size, char **buffer) {
  ifstream stream(loadpath, ios::binary);
  size_t f_size = file_size(loadpath);
  if (stream.is_open() && (long)f_size > offset) {
    size_t size_to_copy = f_size - offset;
    if (size_to_copy > size)
      size_to_copy = size;
    *buffer = new char[size_to_copy];
    stream.seekg(offset, ios::beg);
    stream.read(*buffer, size_to_copy);
    stream.close();
    return size_to_copy;
  }
  return -1;
}

bool delete_file(const string &path) {
  if (remove((char*)path.c_str()) == 0)
    return true;
  return false;
}


vector<string> read_directory(const string& dirpath) {
  DIR* dirp = opendir((char*)dirpath.c_str());
  vector<string> files;
  struct dirent *dp;

  while ((dp = readdir(dirp)) != NULL)
    if (string(".").compare(dp->d_name) != 0 && string("..").compare(dp->d_name) != 0)
      files.push_back(dp->d_name);

  closedir(dirp);
  return files;
}


size_t file_size(const string &path) {
  ifstream stream(path, ios::binary);
  if (stream.is_open()) {
    long begin = stream.tellg();
    stream.seekg(0, ios::end);
    size_t size = stream.tellg() - begin;
    stream.seekg(stream.beg);
    stream.close();
    return size;
  }
  return 0;
}
