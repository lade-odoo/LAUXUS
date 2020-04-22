#ifndef __APP_HPP__
#define __APP_HPP__

#include <string>
#include <fuse.h>

#include "sgx_urts.h"

using namespace std;


class App {
  public:
    static void init(const string &binary_path);

    static void* fuse_init(struct fuse_conn_info *conn);
    static int nexus_create();
    static int nexus_load();
    static int nexus_login(const char *sk_path, const char *user_uuid);

    static void fuse_destroy(void* private_data);
    static int nexus_destroy();

    static int fuse_getattr(const char *path, struct stat *stbuf);
    static int fuse_fgetattr(const char *path, struct stat *stbuf, struct fuse_file_info *);
    static int fuse_open(const char *filepath, struct fuse_file_info *);
    static int fuse_create(const char *filepath, mode_t mode, struct fuse_file_info *);
    static int fuse_read(const char *filepath, char *buf, size_t size, off_t offset, struct fuse_file_info *);
    static int fuse_write(const char *filepath, const char *data, size_t size, off_t offset, struct fuse_file_info *);
    static int fuse_unlink(const char *filepath);

    static int fuse_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi);

    static int fuse_mkdir(const char *dirpath, mode_t);
    static int fuse_rmdir(const char *dirpath);
    static int fuse_opendir(const char *dirpath, struct fuse_file_info *);

    static int nexus_create_user(const char *username, const char *pk_file, const char *sk_file);
    static int nexus_add_user(const char *username, const char *pk_file);
    static int nexus_remove_user(const char *user_uuid);

    static int nexus_load_node(const char *path);
    static int nexus_edit_user_entitlement(const char *user_uuid, const char *path, const unsigned char rights);

  private:
    static int init_enclave();
    static void destroy_enclave();

    static int nexus_login();
};

#endif /*__APP_HPP__*/
