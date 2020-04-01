#include "../utils/serialization.hpp"

#include <string>
#include <vector>
#include <fstream>
#include <iostream>
#include <stdio.h>
#include <sys/types.h>
#include <dirent.h>


int dump(const std::string &dumppath, const size_t size, const char *buffer) {
  std::ofstream stream(dumppath, std::ios::out | std::ios::binary);
  if (stream.is_open()) {
    stream.write(buffer, size);
    stream.close();
    return size;
  }
  return -1;
}

int dump_with_offset(const std::string &dumppath, const long offset, const size_t size, const char *buffer) {
  std::ofstream stream(dumppath,  std::ios::out | std::ios::binary);
  if (stream.is_open() && (long)file_size(dumppath) >= offset) {
    stream.seekp(offset, std::ios::beg);
    stream.write(buffer, size);
    stream.close();
    return size;
  }
  return -1;
}

int load(const std::string &loadpath, char **buffer) {
  std::ifstream stream(loadpath, std::ios::binary);
  if (stream.is_open()) {
    size_t size = file_size(loadpath);
    *buffer = new char[size];
    stream.read(*buffer, size);
    stream.close();
    return size;
  }
  return -1;
}

int load_with_offset(const std::string &loadpath, const long offset, const size_t size, char **buffer) {
  std::ifstream stream(loadpath, std::ios::binary);
  if (stream.is_open() && (long)file_size(loadpath) >= offset) {
    size_t size_to_copy = file_size(loadpath);
    if (size_to_copy > size)
      size_to_copy = size;
    *buffer = new char[size_to_copy];
    stream.read(*buffer, size_to_copy);
    stream.close();
    return size_to_copy;
  }
  return -1;
}

bool delete_file(const std::string &path) {
  if (remove((char*)path.c_str()) == 0)
    return true;
  return false;
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


size_t file_size(const std::string &path) {
  std::ifstream stream(path, std::ios::binary);
  if (stream.is_open()) {
    long begin = stream.tellg();
    stream.seekg(0, std::ios::end);
    size_t size = stream.tellg() - begin;
    stream.seekg(stream.beg);
    stream.close();
    return size;
  }
  return -1;
}
