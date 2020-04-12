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
    static int nexus_login(const char *sk_path, int user_id);

    static void fuse_destroy(void* private_data);
    static int nexus_destroy();

    static int fuse_getattr(const char *path, struct stat *stbuf);
    static int fuse_fgetattr(const char *path, struct stat *stbuf, struct fuse_file_info *);
    static int fuse_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi);
    static int fuse_open(const char *filepath, struct fuse_file_info *);
    static int fuse_create(const char *filepath, mode_t mode, struct fuse_file_info *);
    static int fuse_read(const char *filepath, char *buf, size_t size, off_t offset, struct fuse_file_info *);
    static int fuse_write(const char *filepath, const char *data, size_t size, off_t offset, struct fuse_file_info *);
    static int fuse_unlink(const char *filepath);

    static int nexus_create_user(const char *username, const char *pk_file, const char *sk_file);
    static int nexus_add_user(const char *username, const char *pk_file);
    static int nexus_remove_user(int user_id);
    static int nexus_edit_user_policy(const int user_id, const char *filepath, const unsigned char policy);

  private:
    static int init_enclave();
    static void destroy_enclave();

    static int nexus_login();

    static int retrieve_nexus_content();
    static int retrieve_nexus_meta();
    static int retrieve_nexus_ciphers();
    static int retrieve_nexus_audits();

    static int nexus_write_metadata(const string &filename);
    static int nexus_write_encryption(const string &filename, long offset, size_t updated_size);
    static int nexus_append_reason(const string &filename);
    static int nexus_delete_file(const string &dir, const string &filename);
};

#endif /*__APP_HPP__*/
