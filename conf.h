/*
  Copyright (C) 2017 Christof Efkemann.
  This file is part of nlddcd.

  nlddcd is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  nlddcd is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with nlddcd.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef _NLDDCD_CONF_H_
#define _NLDDCD_CONF_H_

#include <stdbool.h>
#include <netinet/in.h>

#include <ev.h>

typedef struct interface_status {
    ev_timer timeout;
    const char *ifname;
    const char *url;
    const char *login;
    const char *password;
    const char *domain;
    struct in_addr  local_ipaddr;
    struct in_addr  dns_ipaddr;
    struct in6_addr local_ip6addr;
    struct in6_addr dns_ip6addr;
    bool local_ipaddr_set;
    bool dns_ipaddr_set;
    bool local_ip6addr_set;
    bool dns_ip6addr_set;
    bool resolved;
    struct interface_status *next;
} interface_status_t;


bool read_config(const char *cfgfile, interface_status_t **if_stat_head);
void cleanup_config(void);

#endif
