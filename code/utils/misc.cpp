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
  return clean_path(filepath.substr(0, index + 1));
}

string get_relative_path(const string &filepath) {
  size_t index = filepath.find_last_of("/");
  return clean_path(filepath.substr(index+1));
}

string get_parent_path(const string &path) {
  size_t index = path.find("/");
  if (index == string::npos)
    return path;
  return clean_path(path.substr(0, index+1));
}

string get_child_path(const string &path) {
  size_t index = path.find("/");
  if (index == string::npos)
    return "";
  return clean_path(path.substr(index+1));
}

string clean_path(const string &path) {
  string trimmed = path;
  size_t position;
  while ((position = trimmed.find("//")) != string::npos)
    trimmed = trimmed.replace(position, 2, "/");
  while (trimmed.length() > 1 && trimmed.back() == '/')
    trimmed.pop_back();

  return trimmed;
}


int create_directory(const string &dirpath) {
  return system((char*)("mkdir " + dirpath).c_str());
}
