#include "../utils/misc.hpp"

#include <string>
#include <vector>


std::vector<std::string> tokenize(const char *entries, const char separator) {
  std::string str_entries(entries);
  std::vector<std::string> tokens;
  size_t pos = 0, found = std::string::npos;

  do {
    found = str_entries.find(separator, pos);
    size_t length = found - pos;
    if (length == 0) {
      pos = found + 1;
      continue;
    }
    std::string filename = str_entries.substr(pos, length);
    tokens.push_back(filename);
    pos = found + 1;
  } while(found != std::string::npos);

  return tokens;
}


std::string get_directory(const std::string &filepath) {
  std::size_t index = filepath.find_last_of("/");
  return filepath.substr(0, index);
}

std::string get_filename(const std::string &filepath) {
  std::size_t index = filepath.find_last_of("/");
  return filepath.substr(index + 1);
}
