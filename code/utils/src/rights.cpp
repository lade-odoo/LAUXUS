#include "../headers/rights.hpp"


lauxus_right_t lauxus_create_rights(unsigned int o, unsigned int r, unsigned int w, unsigned int e) {
  lauxus_right_t rights;
  rights.owner = o;
  rights.read = r;
  rights.write = w;
  rights.exec = e;
  return rights;
}
lauxus_right_t lauxus_owner_right() { return lauxus_create_rights(1, 1, 1, 1); }
lauxus_right_t lauxus_read_right() { return lauxus_create_rights(0, 1, 0, 0); }
lauxus_right_t lauxus_write_right() { return lauxus_create_rights(0, 0, 1, 0); }
lauxus_right_t lauxus_no_rights() { return lauxus_create_rights(0, 0, 0, 0); }

bool lauxus_has_rights(lauxus_right_t min_rights, lauxus_right_t rights) {
  if (rights.owner == 1)
    return true;

  if ((min_rights.read == 1 && rights.read == 0) ||
      (min_rights.write == 1 && rights.write == 0) ||
      (min_rights.exec == 1 && rights.exec == 0))
    return false;

  return true;
}
