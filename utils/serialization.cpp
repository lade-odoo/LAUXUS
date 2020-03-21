#include "../utils/serialization.hpp"

#include <string>
#include <fstream>
#include <iostream>
#include <stdio.h>


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


int delete_file(const std::string &path) {
  return remove((char*)path.c_str());
}
