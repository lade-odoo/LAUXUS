#include "../headers/fuse.hpp"


void* fuse_init(struct fuse_conn_info *conn) {
  if (lauxus_load() < 0) {
    cout << "Failed to load the filesystem !" << endl;
    exit(1);
  }
  struct lauxus_options *options = (struct lauxus_options*) fuse_get_context()->private_data;
  if (lauxus_login(options->sk_u, options->u_uuid) < 0) {
    cout << "Failed to login in the filesystem !" << endl;
    exit(1);
  }

  return &ENCLAVE_ID;
}

void fuse_destroy(void* private_data) {
  if (lauxus_destroy() < 0)
    exit(1);
}


int fuse_getattr(const char *path, struct stat *stbuf) {
	memset(stbuf, 0, sizeof(struct stat));
  stbuf->st_uid = getuid();
  stbuf->st_gid = getgid();

  int ret, entry_type;
  string cleaned_path = clean_path(path);
  sgx_status_t sgx_status = sgx_entry_type(ENCLAVE_ID, &entry_type, (char*)cleaned_path.c_str());
  if (!is_ecall_successful(sgx_status, "[SGX] Fail to check entry type !"))
    return -EPROTO;
  if (entry_type == -ENOENT)
    return -ENOENT;

  sgx_status = sgx_get_times(ENCLAVE_ID, &ret, (char*)cleaned_path.c_str(), &stbuf->st_atime, &stbuf->st_mtime, &stbuf->st_ctime);
  if (!is_ecall_successful(sgx_status, "[SGX] Fail to load node times !", ret))
    return -EPROTO;

  lauxus_right_t rights;
  sgx_status = sgx_get_user_entitlement(ENCLAVE_ID, &ret, (char*)cleaned_path.c_str(), &rights);
  if (!is_ecall_successful(sgx_status, "[SGX] Fail to load file attribute !", ret))
    return -EPROTO;

  if (entry_type == EEXIST) {
    stbuf->st_mode = S_IFREG | (rights.exec*00100 + rights.write*00200 + rights.read*00400); // 3 LSB base 8
    stbuf->st_nlink = 1;

    sgx_status = sgx_file_size(ENCLAVE_ID, &ret, (char*)cleaned_path.c_str());
    if (!is_ecall_successful(sgx_status, "[SGX] Fail to load file size !", ret))
      return -EPROTO;

    stbuf->st_size = ret;
  } else if (entry_type == EISDIR) {
    stbuf->st_mode = S_IFDIR | (rights.exec*00100 + rights.write*00200 + rights.read*00400); // 3 LSB base 8
    stbuf->st_nlink = 2;
  }

  return 0;
}
int fuse_fgetattr(const char *path, struct stat *stbuf, struct fuse_file_info *) {
  return fuse_getattr(path, stbuf);
}


int fuse_open(const char *filepath, struct fuse_file_info *fi) {
  string path = clean_path(filepath);
  int ret;
  // sgx_status_t sgx_status = sgx_entry_type(ENCLAVE_ID, &ret, (char*)path.c_str());
  // if (ret == -ENOENT)
  //   return -ENOENT;
  // if (ret == EISDIR)
  //   return -EPROTO;
  // if (!is_ecall_successful(sgx_status, "[SGX] Fail to check entry type !"))
  //   return -EPROTO;

  lauxus_right_t asked_rights = {0, 0, 0, 0};
  if ((fi->flags & O_RDONLY) == O_RDONLY)
    asked_rights.read = 1;
  if ((fi->flags & O_WRONLY) == O_WRONLY)
    asked_rights.write = 1;
  if ((fi->flags & O_RDWR) == O_RDWR) {
    asked_rights.read = 1;
    asked_rights.write = 1;
  }

  sgx_status_t sgx_status = sgx_open_file(ENCLAVE_ID, &ret, (char*)path.c_str(), asked_rights);
  if (!is_ecall_successful(sgx_status, "[SGX] Fail to open file !"))
    return -EPROTO;
  return ret;
}

int fuse_release(const char *filepath, struct fuse_file_info *fi) {
	string path = clean_path(filepath);
  int ret;
  // sgx_status_t sgx_status = sgx_entry_type(ENCLAVE_ID, &ret, (char*)path.c_str());
  // if (ret == -ENOENT)
  //   return -ENOENT;
  // if (ret == EISDIR)
  //   return -EPROTO;
  // if (!is_ecall_successful(sgx_status, "[SGX] Fail to check entry type !"))
  //   return -EPROTO;

  sgx_status_t sgx_status = sgx_close_file(ENCLAVE_ID, &ret, (char*)path.c_str());
  if (!is_ecall_successful(sgx_status, "[SGX] Fail to open file !"))
    return -EPROTO;
  return ret;
}

int fuse_create(const char *filepath, mode_t mode, struct fuse_file_info *) {
  string path = clean_path(filepath);
  int ret;
  // sgx_status_t sgx_status = sgx_entry_type(ENCLAVE_ID, &ret, (char*)path.c_str());
  // if (ret != -ENOENT)
  //   return -ret;
  // if (!is_ecall_successful(sgx_status, "[SGX] Fail to get node type !"))
  //   return -EPROTO;

  sgx_status_t sgx_status = sgx_create_file(ENCLAVE_ID, &ret, "...", (char*)path.c_str());
  if (!is_ecall_successful(sgx_status, "[SGX] Fail to create file !"))
    return -EPROTO;

  return (ret < 0) ? ret : 0;
}

int fuse_read(const char *filepath, char *buf, size_t size, off_t offset, struct fuse_file_info *) {
  string path = clean_path(filepath);
  int ret;
  // sgx_status_t sgx_status = sgx_entry_type(ENCLAVE_ID, &ret, (char*)path.c_str());
  // if (ret == -ENOENT)
  //   return -ENOENT;
  // if (!is_ecall_successful(sgx_status, "[SGX] Fail to check entry type !") || ret != EEXIST)
  //   return -EPROTO;

  sgx_status_t sgx_status = sgx_read_file(ENCLAVE_ID, &ret, "...", (char*)path.c_str(), (long)offset, size, (uint8_t*)buf);
  if (!is_ecall_successful(sgx_status, "[SGX] Fail to read file !"))
    return -EPROTO;

  return ret;
}

int fuse_write(const char *filepath, const char *data, size_t size, off_t offset, struct fuse_file_info *fi) {
  string path = clean_path(filepath);
  int ret;
  // sgx_status_t sgx_status = sgx_entry_type(ENCLAVE_ID, &ret, (char*)path.c_str());
  // if (ret == -ENOENT)
  //   return -ENOENT;
  // if (!is_ecall_successful(sgx_status, "[SGX] Fail to check entry type !") || ret != EEXIST)
  //   return -EPROTO;

  sgx_status_t sgx_status = sgx_write_file(ENCLAVE_ID, &ret, "...", (char*)path.c_str(), (long)offset, size, (uint8_t*)data);
  if (!is_ecall_successful(sgx_status, "[SGX] Fail to write file !"))
    return -EPROTO;

  return ret;
}

int fuse_truncate(const char *filepath, off_t offset) {
  string path = clean_path(filepath);
  int ret;
  // sgx_status_t sgx_status = sgx_entry_type(ENCLAVE_ID, &ret, (char*)path.c_str());
  // if (ret == -ENOENT)
  //   return -ENOENT;
  // if (!is_ecall_successful(sgx_status, "[SGX] Fail to check entry type !") || ret != EEXIST)
  //   return -EPROTO;

  sgx_status_t sgx_status = sgx_truncate_file(ENCLAVE_ID, &ret, (char*)path.c_str(), (long)offset);
  if (!is_ecall_successful(sgx_status, "[SGX] Fail to truncate file !"))
    return -EPROTO;

  return ret;
}

int fuse_unlink(const char *filepath) {
  string path = clean_path(filepath);
  int ret;
  // sgx_status_t sgx_status = sgx_entry_type(ENCLAVE_ID, &ret, (char*)path.c_str());
  // if (ret == -ENOENT)
  //   return -ENOENT;
  // if (!is_ecall_successful(sgx_status, "[SGX] Fail to check entry type !") || ret != EEXIST)
  //   return -EPROTO;

  sgx_status_t sgx_status = sgx_unlink(ENCLAVE_ID, &ret, "...", (char*)path.c_str());
  if (!is_ecall_successful(sgx_status, "[SGX] Fail to unlink entry !"))
    return -EPROTO;

  return 0;
}


int fuse_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi) {
  filler(buf, ".", NULL, 0);
  filler(buf, "..", NULL, 0);

  int ret;
  string cleaned_path = clean_path(path);
  sgx_status_t sgx_status = sgx_ls_buffer_size(ENCLAVE_ID, &ret, (char*)cleaned_path.c_str());
  if (!is_ecall_successful(sgx_status, "[SGX] Fail to load ls buffer size !"))
    return -EPROTO;

  const size_t buffer_size = ret;
  char buffer[buffer_size];
  sgx_status = sgx_readdir(ENCLAVE_ID, &ret, (char*)cleaned_path.c_str(), BUFFER_SEPARATOR, buffer_size, buffer);
  if (!is_ecall_successful(sgx_status, "[SGX] Fail to load directory entries !"))
    return -EPROTO;

  vector<string> files = tokenize(buffer_size, buffer, BUFFER_SEPARATOR);
  for (auto it = files.begin(); it != files.end(); it++) {
    filler(buf, (char*)it->c_str(), NULL, 0);
  }

  return 0;
}

int fuse_mkdir(const char *dirpath, mode_t) {
  string path = clean_path(dirpath);
  int ret;
  // sgx_status_t sgx_status = sgx_entry_type(ENCLAVE_ID, &ret, (char*)path.c_str());
  // if (ret != -ENOENT)
  //   return -ret;
  // if (!is_ecall_successful(sgx_status, "[SGX] Fail to check entry type !"))
  //   return -EPROTO;

  sgx_status_t sgx_status = sgx_mkdir(ENCLAVE_ID, &ret, "...", (char*)path.c_str());
  if (!is_ecall_successful(sgx_status, "[SGX] Fail to create directory !"))
    return -EPROTO;

  return (ret < 0) ? ret : 0;
}

int fuse_rmdir(const char *dirpath) {
  string path = clean_path(dirpath);
  int ret;
  // sgx_status_t sgx_status = sgx_entry_type(ENCLAVE_ID, &ret, (char*)path.c_str());
  // if (ret == -ENOENT)
  //   return -ENOENT;
  // if (!is_ecall_successful(sgx_status, "[SGX] Fail to check entry type !") || ret != EISDIR)
  //   return -EPROTO;

  sgx_status_t sgx_status = sgx_rmdir(ENCLAVE_ID, &ret, "..." , (char*)path.c_str());
  if (!is_ecall_successful(sgx_status, "[SGX] Fail to delete directory !"))
    return -EPROTO;

  return 0;
}
