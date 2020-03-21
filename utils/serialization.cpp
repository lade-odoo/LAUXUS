#include "../utils/serialization.hpp"

#include <string>
#include <vector>
#include <fstream>
#include <iostream>
#include <stdio.h>
#include <sys/types.h>
#include <dirent.h>


void dump(const std::string &dumppath, const size_t size, const char *buffer) {
  std::ofstream stream;
  stream.open(dumppath, std::ios::out | std::ios::binary);
  stream.write(buffer, size);
  stream.close();
}

void dump_with_offset(const std::string &dumppath, const long offset, const size_t size, const char *buffer) {
  std::ofstream stream(dumppath,  std::ios::out | std::ios::binary);
  stream.seekp(offset, std::ios::beg);
  stream.write(buffer, size);
  stream.close();
}

size_t load(const std::string &loadpath, char **buffer) {
  std::ifstream stream;
  stream.open(loadpath, std::ios::binary);
  long begin = stream.tellg();
  stream.seekg(0, std::ios::end);
  size_t size = stream.tellg() - begin;
  stream.seekg(stream.beg);

  *buffer = new char[size];
  stream.read(*buffer, size);
  stream.close();
  return size;
}

size_t load_with_offset(const std::string &loadpath, const long offset, const size_t size, char **buffer) {
  std::ifstream stream;
  stream.open(loadpath, std::ios::binary);
  long begin = stream.tellg();
  stream.seekg(0, std::ios::end);
  size_t size_to_copy = stream.tellg() - begin;
  stream.seekg(stream.beg);
  if (size_to_copy > size)
    size_to_copy = size;

  *buffer = new char[size_to_copy];
  stream.read(*buffer, size_to_copy);
  stream.close();
  return size_to_copy;
}


int delete_file(const std::string &path) {
  return remove((char*)path.c_str());
}


std::vector<std::string> read_directory(const std::string& dirpath) {
  DIR* dirp = opendir((char*)dirpath.c_str());
  std::vector<std::string> files;
  struct dirent *dp;

  while ((dp = readdir(dirp)) != NULL)
    if (std::string(".").compare(dp->d_name) != 0 && std::string("..").compare(dp->d_name) != 0)
      files.push_back(dp->d_name);

  closedir(dirp);
  return files;
}
