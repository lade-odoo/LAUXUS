#include "../headers/misc.hpp"


string get_directory_path(const string &path) {
  string cleaned = clean_path(path);
  size_t index = cleaned.find_last_of("/");
  return clean_path(cleaned.substr(0, index + 1));
}

string get_relative_path(const string &path) {
  string cleaned = clean_path(path);
  size_t index = cleaned.find_last_of("/");
  return clean_path(cleaned.substr(index + 1));
}

string get_parent_path(const string &path) {
  string cleaned = clean_path(path);
  size_t index = cleaned.find("/");
  if (index == string::npos)
    return path;
  return clean_path(cleaned.substr(0, index + 1));
}

string get_child_path(const string &path) {
  string cleaned = clean_path(path);
  size_t index = cleaned.find("/");
  if (index == string::npos)
    return "";
  return clean_path(cleaned.substr(index + 1));
}

string clean_path(const string &path) {
  string trimmed = path;
  size_t position;
  while ((position = trimmed.find("//")) != string::npos)
    trimmed = trimmed.replace(position, 2, "/");
  while (trimmed.length() > 1 && trimmed[trimmed.length()-1] == '/')
    trimmed.pop_back();

  return trimmed;
}
