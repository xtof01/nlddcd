#ifndef _NLDDCD_NET_H_
#define _NLDDCD_NET_H_

#include <stdbool.h>

#include "conf.h"

void perform_ddns_update(interface_status_t *if_stat);
void resolve_domain(interface_status_t *if_stat);
bool init_net(void);
void cleanup_net(void);

#endif
