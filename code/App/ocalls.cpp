#include "ocalls.hpp"

#include "utils/headers/serialisation.hpp"


void EMUL_API ocall_print(const char* str) {
  printf("%s\n", str);
}

int EMUL_API ocall_get_current_time(time_t *ret_time) {
  time_t current = time(NULL);
  memcpy(ret_time, &current, sizeof(time_t));
  return 0;
}


int EMUL_API ocall_dump(const char *path, size_t size, const uint8_t *content) {
  string tmp(path);
  return dump(tmp, size, content);
}
int EMUL_API ocall_dump_in_dir(const char *dir, const lauxus_uuid_t *u_uuid, size_t size, const uint8_t *content) {
  string path(dir); path.append("/"); path.append(u_uuid->v);
  return dump(path, size, content);
}
int EMUL_API ocall_dump_append_in_dir(const char *dir, const lauxus_uuid_t *u_uuid, size_t size, const uint8_t *content) {
  string path(dir); path.append("/"); path.append(u_uuid->v);
  return dump_append(path, size, content);
}
int EMUL_API ocall_dump_with_offset_in_dir(const char *dir, const lauxus_uuid_t *u_uuid, long offset, size_t size, const uint8_t *content) {
  string path(dir); path.append("/"); path.append(u_uuid->v);
  return dump_with_offset(path, offset, size, content);
}


int EMUL_API ocall_load_file(const char *dir, const lauxus_uuid_t *u_uuid, long offset, size_t size, uint8_t *content) {
  string path(dir); path.append("/"); path.append(u_uuid->v);
  return load_with_offset(path, offset, size, content);
}


int EMUL_API ocall_file_size(const char *dir, const lauxus_uuid_t *u_uuid) {
  string path(dir); path.append("/"); path.append(u_uuid->v);
  return file_size(path);
}


int EMUL_API ocall_delete_from_dir(const char *dir, const lauxus_uuid_t *u_uuid) {
  string path(dir); path.append("/"); path.append(u_uuid->v);
  remove((char*)path.c_str());
  return 0;
}
