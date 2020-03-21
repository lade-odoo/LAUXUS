#define FUSE_USE_VERSION 29

#include <stdio.h>
#include <vector>
#include <iostream>
#include <fuse.h>
#include <sys/types.h>
#include <unistd.h>

#include "Enclave_u.h"
#include "sgx_urts.h"
#include "sgx_utils/sgx_utils.h"
#include "../utils/serialization.hpp"
#include "../utils/misc.hpp"

/* Global EID shared by multiple threads */
static sgx_enclave_id_t ENCLAVE_ID;
static const char* BINARY_NAME;
static const char BUFFER_SEPARATOR = 0x1C;
static std::string NEXUS_DIR, META_PATH, ENCR_PATH;


// OCall implementations
void ocall_print(const char* str) {
  printf("%s\n", str);
}



static int nexus_write_metadata(const std::string &filename) {
  int ret;
  sgx_metadata_size(ENCLAVE_ID, &ret, (char*)filename.c_str());
  const size_t buffer_size = ret; char *buffer = (char*) malloc(buffer_size);

  sgx_dump_metadata(ENCLAVE_ID, &ret, (char*)filename.c_str(), buffer_size, buffer);
  dump(META_PATH + "/" + filename, buffer_size, buffer);

  free(buffer);
  return ret;
}

static int nexus_write_encryption(const std::string &filename, long offset, size_t updated_size) {
  int ret;
  sgx_encryption_size(ENCLAVE_ID, &ret, (char*)filename.c_str(), offset, updated_size);
  const size_t buffer_size = ret; char *buffer = (char*) malloc(buffer_size);

  sgx_dump_encryption(ENCLAVE_ID, &ret, (char*)filename.c_str(), offset, updated_size, buffer_size, buffer);
  dump_with_offset(ENCR_PATH + "/" + filename, ret, buffer_size, buffer); // dump with return offset

  free(buffer);
  return ret;
}



static void* nexus_init(struct fuse_conn_info *conn) {
  std::string binary_directory = get_directory(std::string(BINARY_NAME));
  std::string path_token = NEXUS_DIR + "/enclave.token";
  std::string path_so = NEXUS_DIR + "/enclave.signed.so";
  if (initialize_enclave(&ENCLAVE_ID, path_token, path_so) < 0) {
    std::cout << "Fail to initialize enclave." << std::endl;
    exit(1);
  }

  int ret;
  sgx_status_t status = sgx_init_filesystem(ENCLAVE_ID, &ret, (char*)binary_directory.c_str());
  if (status != SGX_SUCCESS) {
    std::cout << "Fail to initialize file system." << std::endl;
    exit(1);
  }

  return &ENCLAVE_ID;
}

static void nexus_destroy(void* private_data) {
  int ret;

  sgx_status_t status = sgx_destroy_filesystem(ENCLAVE_ID, &ret);
  if (status != SGX_SUCCESS) {
    std::cout << "Fail to destroy the file system." << std::endl;
    exit(1);
  }
  sgx_destroy_enclave(ENCLAVE_ID);
}


static int nexus_getattr(const char *path, struct stat *stbuf) {
	memset(stbuf, 0, sizeof(struct stat));
  stbuf->st_uid = getuid();
  stbuf->st_gid = getgid();
  stbuf->st_atime = stbuf->st_mtime = stbuf->st_ctime = time(NULL);

	if (strcmp(path, "/") == 0) {
		stbuf->st_mode = S_IFDIR | 0777;
		stbuf->st_nlink = 2;
    return 0;
	}

  int ret;
  std::string filename = get_filename(path);
  sgx_status_t status = sgx_isfile(ENCLAVE_ID, &ret, (char*)filename.c_str());

  if (ret == EEXIST) {
    stbuf->st_mode = S_IFREG | 0777;
    stbuf->st_nlink = 1;
    sgx_file_size(ENCLAVE_ID, &ret, (char*)filename.c_str());
    stbuf->st_size = ret;
  } else {
    return -ENOENT;
  }
  return 0;
}

static int nexus_fgetattr(const char *path, struct stat *stbuf,
                   struct fuse_file_info *) {
  return nexus_getattr(path, stbuf);
}


static int nexus_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                         off_t offset, struct fuse_file_info *fi) {
  filler(buf, ".", NULL, 0);
  filler(buf, "..", NULL, 0);

  int ret;
  sgx_ls_buffer_size(ENCLAVE_ID, &ret);
  const size_t buffer_size = ret; char *buffer = (char*) malloc(buffer_size);
  sgx_readdir(ENCLAVE_ID, &ret, BUFFER_SEPARATOR, buffer_size, buffer);
  std::vector<std::string> files = tokenize(buffer, BUFFER_SEPARATOR);
  for (auto it = files.begin(); it != files.end(); it++) {
    filler(buf, (char*)it->c_str(), NULL, 0);
  }

  free(buffer);
  return 0;
}


static int nexus_open(const char *filepath, struct fuse_file_info *) {
  std::string filename = get_filename(filepath);
  int ret;
  sgx_isfile(ENCLAVE_ID, &ret, (char*)filename.c_str());
  if (ret == -ENOENT)
    return -ENOENT;
  return 0;
}

static int nexus_create(const char *filepath, mode_t mode, struct fuse_file_info *) {
  std::string filename = get_filename(filepath);
  int ret;
  sgx_isfile(ENCLAVE_ID, &ret, (char*)filename.c_str());
  if (ret == EEXIST)
    return -EEXIST;
  sgx_create_file(ENCLAVE_ID, &ret, (char*)filename.c_str());

  nexus_write_metadata(filename);

  return 0;
}

static int nexus_read(const char *filepath, char *buf, size_t size, off_t offset,
                      struct fuse_file_info *) {
  std::string filename = get_filename(filepath);
  int ret;
  sgx_isfile(ENCLAVE_ID, &ret, (char*)filename.c_str());
  if (ret == -ENOENT)
    return -ENOENT;

  sgx_read_file(ENCLAVE_ID, &ret, (char*)filename.c_str(), (long)offset, size, buf);
  return ret;
}

static int nexus_write(const char *filepath, const char *data, size_t size, off_t offset,
                struct fuse_file_info *) {
  std::string filename = get_filename(filepath);
  int ret;
  sgx_isfile(ENCLAVE_ID, &ret, (char*)filename.c_str());
  if (ret == -ENOENT)
    return -ENOENT;
  sgx_write_file(ENCLAVE_ID, &ret, (char*)filename.c_str(), (long)offset, size, data);

  nexus_write_metadata(filename);
  nexus_write_encryption(filename, (long)offset, size);

  return ret;
}

static int nexus_unlink(const char *filepath) {
  std::string filename = get_filename(filepath);
  int ret;
  sgx_isfile(ENCLAVE_ID, &ret, (char*)filename.c_str());
  if (ret == -ENOENT)
    return -ENOENT;

  sgx_unlink(ENCLAVE_ID, &ret, (char*)filename.c_str());
  delete_file(META_PATH + "/" + filename);
  return ret;
}



static struct fuse_operations nexus_oper;

int main(int argc, char **argv) {
  BINARY_NAME = argv[0];
  NEXUS_DIR = get_directory(std::string(BINARY_NAME)) + "/.nexus";
  META_PATH = NEXUS_DIR + "/metadata"; ENCR_PATH = NEXUS_DIR + "/ciphers";
  if (system((char*)("mkdir " + META_PATH).c_str()) < 0)
    exit(1);
  if (system((char*)("mkdir " + ENCR_PATH).c_str()) < 0)
    exit(1);

  int ret;
  struct fuse_args args = FUSE_ARGS_INIT(argc, argv);


  nexus_oper.init = nexus_init;
  nexus_oper.destroy = nexus_destroy;

  nexus_oper.getattr = nexus_getattr;
  nexus_oper.fgetattr = nexus_fgetattr;

  nexus_oper.readdir = nexus_readdir;

  nexus_oper.open = nexus_open;
  nexus_oper.create = nexus_create;
  nexus_oper.read = nexus_read;
  nexus_oper.write = nexus_write;
  nexus_oper.unlink = nexus_unlink;


  ret = fuse_main(args.argc, args.argv, &nexus_oper, NULL);
  fuse_opt_free_args(&args);
  return ret;
}
