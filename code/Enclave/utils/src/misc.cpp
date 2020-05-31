#include "../headers/misc.hpp"


string sgx_get_directory_path(const string &path) {
  string cleaned = sgx_clean_path(path);
  size_t index = cleaned.find_last_of("/");
  return sgx_clean_path(cleaned.substr(0, index + 1));
}

string sgx_get_relative_path(const string &path) {
  string cleaned = sgx_clean_path(path);
  size_t index = cleaned.find_last_of("/");
  return sgx_clean_path(cleaned.substr(index + 1));
}

string sgx_get_parent_path(const string &path) {
  string cleaned = sgx_clean_path(path);
  size_t index = cleaned.find("/");
  if (index == string::npos)
    return path;
  return sgx_clean_path(cleaned.substr(0, index + 1));
}

string sgx_get_child_path(const string &path) {
  string cleaned = sgx_clean_path(path);
  size_t index = cleaned.find("/");
  if (index == string::npos)
    return "";
  return sgx_clean_path(cleaned.substr(index + 1));
}

string sgx_clean_path(const string &path) {
  string trimmed = path;
  size_t position;
  while ((position = trimmed.find("//")) != string::npos)
    trimmed = trimmed.replace(position, 2, "/");
  while (trimmed.length() > 1 && trimmed[trimmed.length()-1] == '/')
    trimmed.pop_back();

  return trimmed;
}
