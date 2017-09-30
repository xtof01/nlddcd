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
