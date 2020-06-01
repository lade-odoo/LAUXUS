#ifndef __OPTIONS_HPP__
#define __OPTIONS_HPP__

#include "misc.hpp"
#include "fuse.hpp"

#include <fuse.h>
#include <string>

using namespace std;

extern string BINARY_PATH;


struct lauxus_options {
  int new_fs, new_keys, add_user, remove_user, edit_entitlement, show_help;

  char *sk_u, *pk_u, *sk_a, *pk_a, *new_sk_u,  *new_pk_u;
  char *u_uuid, *other_u_uuid;
  char *new_username;
  char *edit_path;
  int owner_right, read_right, write_right, exec_right;
};


struct fuse_args parse_args(int argc, char **argv, struct lauxus_options *options, int *main_mount);

void display_help();


#endif /*__OPTIONS_HPP__*/