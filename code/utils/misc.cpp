#include "../utils/misc.hpp"

#include <string>
#include <vector>

using namespace std;


vector<string> tokenize(const size_t buffer_size, const char *entries, const char separator) {
  string str_entries(entries);
  vector<string> tokens;
  size_t pos = 0, found = string::npos;

  do {
    found = str_entries.find(separator, pos);
    size_t length = found - pos;
    if (pos+length > buffer_size)
      break;
    if (length == 0) {
      pos = found + 1;
      continue;
    }
    string filename = str_entries.substr(pos, length);
    tokens.push_back(filename);
    pos = found + 1;
  } while(found != string::npos);

  return tokens;
}


string get_directory(const string &filepath) {
  size_t index = filepath.find_last_of("/");
  return filepath.substr(0, index);
}

string get_filename(const string &filepath) {
  size_t index = filepath.find_last_of("/");
  return filepath.substr(index+1);
}


int create_directory(const string &dirpath) {
  return system((char*)("mkdir " + dirpath).c_str());
}
