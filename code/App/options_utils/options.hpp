#ifndef __OPTIONS_HPP__
#define __OPTIONS_HPP__

struct nexus_options {
  int new_user, add_user, create_fs, show_help, edit_policies_user, remove_user;
  int edited_user_id, user_id , policy, deleted_user_id;

  char *user_pk_file, *user_sk_file;
	char *new_username, *new_user_pk_file, *new_user_sk_file;
  char *policy_filename;
};


struct fuse_args parse_args(int argc, char **argv, struct nexus_options *options, int *result);

int create_fs(struct nexus_options *options);
int create_user(struct nexus_options *options);
int add_user(struct nexus_options *options);
int remove_user(struct nexus_options *options);
int edit_user_policy(struct nexus_options *options);

void show_help(const char *progname);


#endif /*__OPTIONS_HPP__*/
