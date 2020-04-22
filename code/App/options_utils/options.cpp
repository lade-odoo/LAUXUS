#include "../options_utils/options.hpp"
#include "../../App/App.hpp"
#include "../../App/Enclave_u.h"
#include "../../utils/misc.hpp"
#include "../../utils/serialization.hpp"

#include <assert.h>
#include <iostream>
#include <fuse.h>


#define OPTION(t, p)                           \
    { t, offsetof(struct nexus_options, p), 1 }

static const struct fuse_opt option_spec[] = {
	OPTION("-h", show_help),
	OPTION("--help", show_help),

	OPTION("--user_pk_file=%s", user_pk_file),
	OPTION("--user_sk_file=%s", user_sk_file),
	OPTION("--user_uuid=%s", user_uuid),

	OPTION("--create_fs", create_fs),
	OPTION("--auditor_username=%s", auditor_username),
  OPTION("--auditor_pk_file=%s", auditor_pk_file),
  OPTION("--auditor_sk_file=%s", auditor_sk_file),

	OPTION("--new_user", new_user),
  OPTION("--new_user_pk_file=%s", new_user_pk_file),
  OPTION("--new_user_sk_file=%s", new_user_sk_file),
	OPTION("--new_username=%s", new_username),

  OPTION("--add_user", add_user),

  OPTION("--remove_user", remove_user),
  OPTION("--deleted_user_uuid=%s", deleted_user_uuid),

	OPTION("--edit_policies_user", edit_policies_user),
	OPTION("--policy=%d", policy),
	OPTION("--policy_filename=%s", policy_filename),
	OPTION("--edited_user_uuid=%s", edited_user_uuid),
	FUSE_OPT_END
};


using namespace std;



struct fuse_args parse_args(int argc, char **argv, struct nexus_options *options, int *result) {
  string binary_path = get_directory(string(argv[0]));
  struct fuse_args args = FUSE_ARGS_INIT(argc, argv);

  /* Set defaults -- we have to use strdup so that
	   fuse_opt_parse can free the defaults if other
	   values are specified */
	options->user_pk_file = strdup((char*)(binary_path + "/ecc-256-public-key.spki").c_str());
  options->user_sk_file = strdup((char*)(binary_path + "/ecc-256-private-key.p8").c_str());
  options->auditor_pk_file = strdup((char*)(binary_path + "/auditor_ecc-256-public-key.spki").c_str());
  options->auditor_sk_file = strdup((char*)(binary_path + "/auditor_ecc-256-private-key.p8").c_str());
  options->user_uuid = options->edited_user_uuid = NULL;
  options->policy = -1;

  /* Parse options */
	if (fuse_opt_parse(&args, options, option_spec, NULL) == -1) {
    *result = -1;
		return args;
  }


  bool missing_arg = false;
	if (options->create_fs) {
    cout << "Creating the filesystem ..." << endl;
    if (options->new_username != NULL && options->auditor_username != NULL) {
      *result = create_fs(options);
      return args;
    } else {
      missing_arg = true;
    }
  } else if (options->new_user) {
    cout << "Creating a new user ..." << endl;
    if (options->user_uuid != NULL  && options->new_user_pk_file != NULL && options->new_user_sk_file != NULL && options->new_username != NULL) {
      *result = create_user(options);
      return args;
    } else {
      missing_arg = true;
    }
  } else if (options->add_user) {
    cout << "Adding a new user ..." << endl;
    if (options->user_uuid != NULL && options->new_user_pk_file != NULL && options->new_username != NULL) {
      *result = add_user(options);
      return args;
    } else {
      missing_arg = true;
    }
  } else if (options->remove_user) {
    cout << "Removing a user ..." << endl;
    if (options->user_uuid != NULL  && options->deleted_user_uuid != NULL) {
      *result = remove_user(options);
      return args;
    } else {
      missing_arg = true;
    }
  } else if (options->edit_policies_user) {
    cout << "Updating a user access right ..." << endl;
    if (options->user_uuid != NULL && options->edited_user_uuid != NULL && options->policy_filename != NULL &&
          options->policy >= 0 && options->policy <= 8) {
      *result = edit_user_policy(options);
      return args;
    } else {
      missing_arg = true;
    }
  } else if (options->show_help) {
    cout << "Showing help ..." << endl;
    show_help(argv[0]);
    assert(fuse_opt_add_arg(&args, "--help") == 0);
		args.argv[0][0] = '\0';
    return args;
  } else if (options->user_uuid == NULL) {
    missing_arg = true;
  }

  if (missing_arg) {
    cout << "Missing mandatory argument !" << endl;
    *result = -1;
  } else {
    *result = 0;
  }

  return args;
}


int create_fs(struct nexus_options *options) {
  if (App::nexus_create() < 0)
    return -1;
  cout << "--------- Administrator ---------" << endl;
  if (App::nexus_create_user(options->new_username, options->user_pk_file, options->user_sk_file) < 0)
    return -1;
  cout << "------------ Auditor ------------" << endl;
  if (App::nexus_create_user(options->auditor_username, options->auditor_pk_file, options->auditor_sk_file) < 0)
    return -1;

  App::nexus_destroy();
  cout << "Filesystem successfully created." << endl;
  return 1;
}

int create_user(struct nexus_options *options) {
  if( App::nexus_load() < 0)
    return -1;
  if( App::nexus_login(options->user_sk_file, options->user_uuid) < 0)
    return -1;
  if (App::nexus_create_user(options->new_username, options->new_user_pk_file, options->new_user_sk_file) < 0)
    return -1;

  App::nexus_destroy();
  return 1;
}

int add_user(struct nexus_options *options) {
  if( App::nexus_load() < 0)
    return -1;
  if( App::nexus_login(options->user_sk_file, options->user_uuid) < 0)
    return -1;
  if (App::nexus_add_user(options->new_username, options->new_user_pk_file) < 0)
    return -1;

  App::nexus_destroy();
  return 1;
}

int remove_user(struct nexus_options *options) {
  if( App::nexus_load() < 0)
    return -1;
  if( App::nexus_login(options->user_sk_file, options->user_uuid) < 0)
    return -1;
  if (App::nexus_remove_user(options->deleted_user_uuid) < 0)
    return -1;

  App::nexus_destroy();
  cout << "User successfully removed." << endl;
  return 1;
}

int edit_user_policy(struct nexus_options *options) {
  // if( App::nexus_load_fs(options) < 0)...
  //   return -1;
  //
  // if (App::nexus_edit_user_policy(options->edited_user_uuid, options->policy_filename, options->policy) < 0)
  //   return -1;
  //
  // App::nexus_destroy(NULL);
  // cout << "User successfully added." << endl;
  // return 1;
}


void show_help(const char *progname) {
	printf("usage: %s [options] <mountpoint>\n\n", progname);
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
	       "    --deleted_user_uuidid=<d>   UUID of the user to remove.\n"
	       "------ Editing file access policy for a user ------\n"
	       "    --edit_policies_user        Edit the access right of a user to a file.\n"
	       "    --user_uuid=<s>             UUID of the user who initiate the action.\n"
	       "    --user_sk_file=<s>          Path to the private key of the user who initiated the action.\n"
	       "    --user_pk_file=<s>          Path to the public key of the user who initiated the action.\n"
	       "    --policy_filename=<s>       Path to the file on which the policy should be updated.\n"
	       "    --policy=<d>                The standard access fight to the given file.\n"
	       "    --edited_user_uuid=<d>      UUID of the user to which the access should be updated.\n"
	       "\n");
}
