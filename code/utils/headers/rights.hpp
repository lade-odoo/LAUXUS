#ifndef _RIGHTS_HPP_
#define _RIGHTS_HPP_

#include <stdbool.h>


typedef struct _lauxus_right_t {
  unsigned int owner  : 1;
  unsigned int read   : 1;
  unsigned int write  : 1;
  unsigned int exec   : 1;
} lauxus_right_t;


lauxus_right_t lauxus_create_rights(unsigned int owner, unsigned int read,
                  unsigned int write, unsigned int exec);
lauxus_right_t lauxus_owner_right();
lauxus_right_t lauxus_read_right();
lauxus_right_t lauxus_write_right();
lauxus_right_t lauxus_no_rights();

bool lauxus_has_rights(lauxus_right_t min_right, lauxus_right_t right);


#endif /*__RIGHTS_HPP__*/
