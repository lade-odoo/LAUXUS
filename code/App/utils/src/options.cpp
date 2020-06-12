#include "../headers/options.hpp"


#define OPTION(t, p)                           \
    { t, offsetof(struct lauxus_options, p), 1 }

static const struct fuse_opt option_spec[] = {
  OPTION("--new_fs", new_fs),
  OPTION("--new_keys", new_keys),
  OPTION("--add_user", add_user),
  OPTION("--remove_user", remove_user),
  OPTION("--edit_entitlement", edit_entitlement),
  OPTION("--create_quote", create_quote),
  OPTION("--upload_rk", upload_rk),
  OPTION("--download_rk", download_rk),

	OPTION("--sk_u=%s", sk_u),
	OPTION("--pk_u=%s", pk_u),
	OPTION("--pk_o=%s", pk_o),
	OPTION("--sk_eu=%s", sk_eu),
	OPTION("--pk_eu=%s", pk_eu),
  OPTION("--sk_a=%s", sk_a),
	OPTION("--pk_a=%s", pk_a),
	OPTION("--new_sk_u=%s", new_sk_u),
	OPTION("--new_pk_u=%s", new_pk_u),

	OPTION("--u_uuid=%s", u_uuid),
	OPTION("--other_u_uuid=%s", other_u_uuid),

	OPTION("--new_username=%s", new_username),

	OPTION("--edit_path=%s", edit_path),

  OPTION("--owner_right=%d", owner_right),
	OPTION("--read_right=%d", read_right),
  OPTION("--write_right=%d", write_right),
	OPTION("--exec_right=%d", exec_right),

	OPTION("-h", show_help),
	OPTION("--help", show_help),
	FUSE_OPT_END
};


struct fuse_args parse_args(int argc, char **argv, struct lauxus_options *options, int *result) {
  struct fuse_args args = FUSE_ARGS_INIT(argc, argv);

  /* Set defaults -- we have to use strdup so that
	   fuse_opt_parse can free the defaults if other
	   values are specified */
	options->pk_u = strdup((char*)(BINARY_PATH + "/ecc-256-public-key.spki").c_str());
  options->sk_u = strdup((char*)(BINARY_PATH + "/ecc-256-private-key.p8").c_str());
  options->new_pk_u = strdup((char*)(BINARY_PATH + "/ecc-256-public-key.spki").c_str());
  options->new_sk_u = strdup((char*)(BINARY_PATH + "/ecc-256-private-key.p8").c_str());
  options->pk_o = strdup((char*)(BINARY_PATH + "/other_ecc-256-public-key.spki").c_str());
  options->sk_eu = strdup((char*)(BINARY_PATH + "/enclave_ecc-256-private-key.p8").c_str());
  options->pk_eu = strdup((char*)(BINARY_PATH + "/enclave_ecc-256-public-key.spki").c_str());
  options->pk_a = strdup((char*)(BINARY_PATH + "/auditor_ecc-256-public-key.spki").c_str());
  options->sk_a = strdup((char*)(BINARY_PATH + "/auditor_ecc-256-private-key.p8").c_str());
  options->u_uuid = options->other_u_uuid = NULL;
  options->owner_right = options->read_right = options->write_right = options->exec_right = 0;

  /* Parse options */
  *result = 0;
  bool missing_arg = false;
	if (fuse_opt_parse(&args, options, option_spec, NULL) == -1) {
    *result = -1;
		return args;
  } else if (options->new_fs) {
    if (options->sk_u == NULL || options->pk_u == NULL ||
        options->sk_a == NULL || options->pk_a == NULL)
      *result = -1;
    else
      *result = lauxus_new();
      *result *= lauxus_new_keys(options->sk_u, options->pk_u);
      *result *= lauxus_add_user("admin", options->pk_u);
      *result *= lauxus_new_keys(options->sk_a, options->pk_a);
      *result *= lauxus_add_user("auditor", options->pk_a);
  } else if (options->new_keys) {
    if (options->new_sk_u == NULL || options->new_pk_u == NULL)
      *result = -1;
    else
      *result = lauxus_new_keys(options->new_sk_u, options->new_pk_u);
  } else if (options->add_user) {
    if (options->new_username == NULL || options->pk_o == NULL)
      *result = -1;
    else
      *result = lauxus_add_user(options->new_username, options->pk_o);
  } else if (options->remove_user) {
    if (options->other_u_uuid == NULL)
      *result = -1;
    else
      *result = lauxus_remove_user(options->other_u_uuid);
  } else if (options->edit_entitlement) {
    if (options->edit_path == NULL || options->other_u_uuid == NULL ||
        options->owner_right >= 0 || options->read_right >= 0 ||
        options->write_right >= 0 || options->exec_right >= 0)
      *result = -1;
    else
      *result = lauxus_edit_user_entitlement(options->edit_path, options->other_u_uuid,
                options->owner_right, options->read_right, options->write_right, options->exec_right);
  } else if (options->create_quote) {
    if (options->sk_u == NULL || options->sk_eu == NULL ||
        options->pk_eu == 0 || options->u_uuid == NULL)
      *result = -1;
    else
      *result = lauxus_create_quote(options->sk_u, options->sk_eu, options->pk_eu, options->u_uuid);
  } else if (options->upload_rk) {
    if (options->sk_u == NULL || options->pk_o == NULL || options->other_u_uuid == NULL)
      *result = -1;
    else
      *result = lauxus_get_shared_rk(options->sk_u, options->pk_o, options->other_u_uuid);
  } else if (options->download_rk) {
    if (options->sk_eu == NULL || options->u_uuid == NULL ||
        options->pk_o == NULL || options->other_u_uuid == NULL)
      *result = -1;
    else
      *result = lauxus_retrieve_shared_rk(options->sk_eu, options->u_uuid, options->pk_o, options->other_u_uuid);
  } else if (options->show_help) {
    display_help();
  } else {
    *result = 1;
    if (options->u_uuid == NULL || options->sk_u == NULL)
      *result = -1;
  }

  if (missing_arg) {
    cout << "Missing mandatory argument !" << endl;
    *result = -1;
  } else if (*result == -1)
    cout << "Operation not successful !" << endl;


  return args;
}

void display_help() {
	printf("usage: %s [options] <mountpoint>\n\n", "lauxus");
	printf("File-system specific options:\n"
	       "    -h | --help                 Displays help.\n"
	       "--------------- Running the filesystem --------------\n"
	       "    --user_uuid=<s>             UUID of the user who initiate the action.\n"
	       "    --user_pk_file=<s>          Path to the public key of the user who initiated the action.\n"
	       "    --user_sk_file=<s>          Path to the private key of the user who initiated the action.\n"
	       "-------------- Creating the filesystem --------------\n"
	       "    --create_fs                 Creates a new filesystem from scratch.\n"
	       "    --new_username=<s>          The username of the new user to create.\n"
	       "    --user_sk_file=<s>          Path where to store the private key of the administrator.\n"
	       "    --user_pk_file=<s>          Path where to store the public key of the administrator.\n"
	       "    --auditor_username=<s>      The username of the auditor user.\n"
	       "    --auditor_sk_file=<s>       Path where to store the private key of the auditor.\n"
	       "    --auditor_pk_file=<s>       Path where to store the public key of the auditor.\n"
	       "---------------- Creating a new user ----------------\n"
 	       "    --new_user                  Creates a new users provided its public key.\n"
	       "    --user_uuid=<s>             UUID of the user who initiate the action.\n"
	       "    --user_sk_file=<s>          Path to the private key of the user who initiated the action.\n"
	       "    --user_pk_file=<s>          Path to the public key of the user who initiated the action.\n"
 	       "    --new_user_pk_file=<s>      Path where to store the public key of the new user.\n"
 	       "    --new_user_sk_file=<s>      Path where to store the private key of the new user.\n"
	       "    --new_username=<s>          The username of the new user to create.\n"
	       "---------------- Adding a new user ----------------\n"
 	       "    --add_user                  Creates a new users provided its public key.\n"
	       "    --user_uuid=<s>             UUID of the user who initiate the action.\n"
	       "    --user_sk_file=<s>          Path to the private key of the user who initiated the action.\n"
	       "    --user_pk_file=<s>          Path to the public key of the user who initiated the action.\n"
 	       "    --new_user_pk_file=<s>      Path to the public key of the new user.\n"
	       "    --new_username=<s>          The username of the new user to create.\n"
	       "---------------- Removing a user ------------------\n"
 	       "    --remove_user                  Creates a new users provided its public key.\n"
	       "    --user_uuid=<s>             UUID of the user who initiate the action.\n"
	       "    --user_sk_file=<s>          Path to the private key of the user who initiated the action.\n"
	       "    --user_pk_file=<s>          Path to the public key of the user who initiated the action.\n"
	       "    --deleted_user_uuid=<s>     UUID of the user to remove.\n"
	       "------ Editing user entitlement for a file ------\n"
	       "    --edit_entitlement_user     Edit the access right of a user to a file.\n"
	       "    --user_uuid=<s>             UUID of the user who initiate the action.\n"
	       "    --user_sk_file=<s>          Path to the private key of the user who initiated the action.\n"
	       "    --user_pk_file=<s>          Path to the public key of the user who initiated the action.\n"
	       "    --entitlement_filename=<s>  Path to the file on which the entitlement should be updated.\n"
	       "    --rights=<d>                The standard access fight to the given file.\n"
	       "    --edited_user_uuid=<s>      UUID of the user to which the access should be updated.\n"
	       "\n");
}
