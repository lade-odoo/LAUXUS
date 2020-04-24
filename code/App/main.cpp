#define FUSE_USE_VERSION 29

#include <string>
#include <fuse.h>

#include "../App/options_utils/options.hpp"
#include "../App/App.hpp"
#include "../utils/misc.hpp"


using namespace std;

static struct fuse_operations nexus_oper;


int main(int argc, char **argv) {
  string binary_path =  get_directory_path(string(argv[0]));
  App::init(binary_path);

  nexus_oper.init = App::fuse_init;
  nexus_oper.destroy = App::fuse_destroy;

  nexus_oper.getattr = App::fuse_getattr;
  nexus_oper.fgetattr = App::fuse_fgetattr;
  nexus_oper.open = App::fuse_open;
  nexus_oper.create = App::fuse_create;
  nexus_oper.read = App::fuse_read;
  nexus_oper.write = App::fuse_write;
  nexus_oper.unlink = App::fuse_unlink;

  nexus_oper.readdir = App::fuse_readdir;

  nexus_oper.mkdir = App::fuse_mkdir;
  nexus_oper.rmdir = App::fuse_rmdir;


  struct nexus_options *options = (struct nexus_options*) malloc(sizeof(struct nexus_options));
  int exit = 0;
  struct fuse_args args = parse_args(argc, argv, options, &exit);
  if (exit != 0)
    return exit < 0 ? -1 : 0;

  int ret = fuse_main(args.argc, args.argv, &nexus_oper, (void*)options);
  fuse_opt_free_args(&args);

  return ret;
}
