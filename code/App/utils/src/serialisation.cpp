#include "../headers/serialisation.hpp"


int load(string &path, size_t size, uint8_t *content) {
  return load_with_offset(path, 0, size, content);
}
int load_with_offset(string &path, long offset, size_t size, uint8_t *content) {
  ifstream stream(path, ios::binary);
  size_t f_size = file_size(path);
  if (stream.is_open() && (long)f_size > offset) {
    size_t size_to_copy = f_size - offset;
    if (size_to_copy > size)
      size_to_copy = size;
    stream.seekg(offset, ios::beg);
    stream.read((char*)content, size_to_copy);
    stream.close();
    return size_to_copy;
  }
  return -1;
}


int dump(string &path, size_t size, const uint8_t *content) {
  ofstream stream(path, ios::out | ios::binary | ios::trunc);
  if (stream.is_open()) {
    stream.write((char*)content, size);
    stream.close();
    return size;
  }
  return -1;
}
int dump_append(string &path, size_t size, const uint8_t *content) {
  return dump_with_offset(path, file_size(path), size, content);
}
int dump_with_offset(string &path, long offset, size_t size, const uint8_t *content) {
  if (file_size(path) == 0) {
    ofstream file(path, ios::out | ios::binary);
    file.close();
  }

  ofstream stream(path, ios::in | ios::out | ios::binary);
  if (stream.is_open() && (long)file_size(path) >= offset) {
    stream.seekp(offset, ios::beg);
    stream.write((char*)content, size);
    stream.close();
    return size;
  }
  return -1;
}
int truncate_file(string &path, const long new_size) {
  int res = truncate(path.c_str(), new_size);
	if (res == -1)
		return -1;
  return 0;
}


int file_size(string &path) {
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


int create_directory(string &dirpath) {
  return system((char*)("mkdir " + dirpath).c_str());
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
