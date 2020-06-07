#ifndef __FUSE_HPP__
#define __FUSE_HPP__

#include <fuse.h>
#include <cerrno>
#include <vector>
#include <string>
#include <cstring>
#include <iostream>
#include <unistd.h>
#include <sys/stat.h>

#include "../../../flag.h"
#if EMULATING
#   include "../../../tests/SGX_Emulator/sgx_error.hpp"
#   include "../../../tests/SGX_Emulator/Enclave_u.hpp"
#else
#   include "sgx_error.h"
#   include "Enclave_u.h"
#endif

#include "misc.hpp"
#include "lauxus.hpp"
#include "options.hpp"
#include "../../sgx_utils/sgx_utils.h"

using namespace std;

static const char BUFFER_SEPARATOR = 0x1C;
extern sgx_enclave_id_t ENCLAVE_ID;


void* fuse_init(struct fuse_conn_info *conn);
void fuse_destroy(void* private_data);

int fuse_getattr(const char *path, struct stat *stbuf);
int fuse_fgetattr(const char *path, struct stat *stbuf, struct fuse_file_info *);

int fuse_rename(const char *path, const char *new_path);

int fuse_open(const char *filepath, struct fuse_file_info *fi);
int fuse_release(const char *filepath, struct fuse_file_info *fi);
int fuse_create(const char *filepath, mode_t mode, struct fuse_file_info *);
int fuse_read(const char *filepath, char *buf, size_t size, off_t offset, struct fuse_file_info *);
int fuse_write(const char *filepath, const char *data, size_t size, off_t offset, struct fuse_file_info *fi);
int fuse_truncate(const char *filepath, off_t offset);
int fuse_unlink(const char *filepath);

int fuse_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi);
int fuse_mkdir(const char *dirpath, mode_t);
int fuse_rmdir(const char *dirpath);


#endif /*__FUSE_HPP__*/
