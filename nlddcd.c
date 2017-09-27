#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <getopt.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <signal.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <linux/rtnetlink.h>
#include <libmnl/libmnl.h>
#include <confuse.h>
#include <ev.h>

#include "nlutils.h"


#define DEFAULT_CONF_FILE SYSCONFDIR "/nlddcd.conf"

cfg_t *config;
ev_io nl_watcher;
ev_timer addr_timeout_watcher;
ev_signal stop_watcher;


void syntax(void)
{
    printf("Usage: " PACKAGE_NAME " [OPTIONS]\n");
}


void help(void)
{
    syntax();
    printf("\n"
           "Netlink-based Dynamic DNS Client Daemon.\n"
           "\n"
           "Options:\n"
           "  -h, --help              Show this help message and exit.\n"
           "  -v, --version           Show version info and exit.\n"
           "  -c FILE, --config FILE  Read configuration from FILE.\n");
}


void version(void)
{
    printf(PACKAGE_STRING "\n"
           "Copyright (C) 2017 Christof Efkemann.\n"
           "License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>.\n"
           "This is free software: you are free to change and redistribute it.\n"
           "There is NO WARRANTY, to the extent permitted by law.\n");
}


size_t af_addr_size(unsigned char family)
{
    switch (family) {
    case AF_INET:
        return sizeof(struct in_addr);
    case AF_INET6:
        return sizeof(struct in6_addr);
    default:
        return UINT_MAX;
    }
}

#if 0
int parse_addr_attr_cb(const struct nlattr *attr, void *data)
{
    if (mnl_attr_type_valid(attr, RTA_MAX) < 0)
        return MNL_CB_OK;

    char addr[INET6_ADDRSTRLEN];
    unsigned char ifa_family = (unsigned char)(uintptr_t)data;
    size_t addrsize = af_addr_size(ifa_family);
    int type = mnl_attr_get_type(attr);

    printf("      rta_type: %s\n", ifa_rta_type2str(type));

    switch (type) {
    case IFA_ADDRESS:
    case IFA_LOCAL:
    case IFA_BROADCAST:
    case IFA_ANYCAST:
        if (mnl_attr_validate2(attr, MNL_TYPE_BINARY, addrsize) < 0) {
            perror("mnl_attr_validate2");
            return MNL_CB_ERROR;
        }
        break;

    case IFA_CACHEINFO:
        if (mnl_attr_validate2(attr, MNL_TYPE_BINARY, sizeof (struct ifa_cacheinfo)) < 0) {
            perror("mnl_attr_validate2");
            return MNL_CB_ERROR;
        }
        break;

    case IFA_LABEL:
        if (mnl_attr_validate(attr, MNL_TYPE_NUL_STRING) < 0) {
            perror("mnl_attr_validate");
            return MNL_CB_ERROR;
        }
        break;

    case IFA_FLAGS:
        if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0) {
            perror("mnl_attr_validate");
            return MNL_CB_ERROR;
        }
        break;
    }

    if (type == IFA_ADDRESS) {
        inet_ntop(ifa_family, mnl_attr_get_payload(attr), addr, sizeof addr);
        printf("        address: %s\n", addr);
    }
    if (type == IFA_LOCAL) {
        inet_ntop(ifa_family, mnl_attr_get_payload(attr), addr, sizeof addr);
        printf("        local:   %s\n", addr);
    }
    if (type == IFA_LABEL) {
        printf("        label:   %s\n", mnl_attr_get_str(attr));
    }
    if (type == IFA_BROADCAST) {
        inet_ntop(ifa_family, mnl_attr_get_payload(attr), addr, sizeof addr);
        printf("        brcst:   %s\n", addr);
    }
    if (type == IFA_ANYCAST) {
        inet_ntop(ifa_family, mnl_attr_get_payload(attr), addr, sizeof addr);
        printf("        anycast: %s\n", addr);
    }
    if (type == IFA_CACHEINFO) {
        struct ifa_cacheinfo *ci = mnl_attr_get_payload(attr);

        printf("        ifa_prefered: %u\n", ci->ifa_prefered);
        printf("        ifa_valid:    %u\n", ci->ifa_valid);
        printf("        cstamp:       %u\n", ci->cstamp);
        printf("        tstamp:       %u\n", ci->tstamp);
    }
    if (type == IFA_FLAGS) {
        unsigned int flags = mnl_attr_get_u32(attr);

        printf("        flags:        %s\n", ifa_flags2str(flags));
    }

    return MNL_CB_OK;
}
#endif

void parse_addr_msg(const struct nlmsghdr *nlh)
{
    char ifname[IF_NAMESIZE];
    char addr[INET6_ADDRSTRLEN];
    const struct nlattr *attr;
    const struct ifaddrmsg *ifa = mnl_nlmsg_get_payload(nlh);
    size_t addrsize = af_addr_size(ifa->ifa_family);

    if_indextoname(ifa->ifa_index, ifname);
    /*
    printf("  nlmsg_type:  %s\n", nlmsg_type2str(nlh->nlmsg_type));
    printf("    ifa_family:    %s\n", ifa_family2str(ifa->ifa_family));
    printf("    ifa_prefixlen: %u\n", ifa->ifa_prefixlen);
    printf("    ifa_flags:     %s\n", ifa_flags2str(ifa->ifa_flags));
    printf("    ifa_scope:     %s\n", rtm_scope2str(ifa->ifa_scope));
    printf("    ifa_index:     %s (%d)\n", ifname, ifa->ifa_index);
    */

    mnl_attr_for_each(attr, nlh, sizeof *ifa) {
        if (mnl_attr_type_valid(attr, RTA_MAX) > 0) {
            int type = mnl_attr_get_type(attr);

            if (type == IFA_LOCAL) {
                if (mnl_attr_validate2(attr, MNL_TYPE_BINARY, addrsize) >= 0) {
                    inet_ntop(ifa->ifa_family, mnl_attr_get_payload(attr), addr, sizeof addr);
                    printf("        local:   %s\n", addr);
                }
            }
        }
    }

    //mnl_attr_parse(nlh, sizeof *ifa, parse_addr_attr_cb, (void *)(uintptr_t)ifa->ifa_family);
}


int nl_msg_cb(const struct nlmsghdr *nlh, void *data)
{
    switch (nlh->nlmsg_type) {
    case RTM_NEWADDR:
    //case RTM_DELADDR:
        parse_addr_msg(nlh);
        break;
    }

    return MNL_CB_OK;
}


unsigned int seq, portid;


void receive_nl_msg(struct mnl_socket *nl)
{
    char buf[MNL_SOCKET_BUFFER_SIZE];
    int len;

    len = mnl_socket_recvfrom(nl, buf, sizeof buf);

    if (len > 0) {
        mnl_cb_run(buf, len, 0, 0, nl_msg_cb, NULL);
    }
}


void request_addr_dump(struct mnl_socket *nl)
{
    char buf[MNL_SOCKET_BUFFER_SIZE];
    struct nlmsghdr *nlh;
    struct rtgenmsg *rt;

    memset(buf, 0, sizeof buf);
    nlh = mnl_nlmsg_put_header(buf);
    nlh->nlmsg_type = RTM_GETADDR;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	nlh->nlmsg_seq = ++seq;
    nlh->nlmsg_pid = portid;
    rt = mnl_nlmsg_put_extra_header(nlh, sizeof(struct rtgenmsg));
    rt->rtgen_family = AF_INET;

    if (mnl_socket_sendto(nl, buf, nlh->nlmsg_len) < 0) {
        perror("mnl_socket_sendto");
    }
}


struct mnl_socket *nl_open()
{
    int group = RTNLGRP_IPV4_IFADDR;
    struct mnl_socket *nl;

    nl = mnl_socket_open(NETLINK_ROUTE);
    if (nl != NULL) {
        int fd = mnl_socket_get_fd(nl);

        if (fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK) == 0) {

            if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) == 0) {
                portid = mnl_socket_get_portid(nl);
                seq = time(NULL);

                if (mnl_socket_setsockopt(nl, NETLINK_ADD_MEMBERSHIP,
                                          &group, sizeof group) == 0) {
                    return nl;
                }
                else {
                    perror("mnl_socket_setsockopt");
                }
            }
            else {
                perror("mnl_socket_bind");
            }
        }
        else {
            perror("fcntl");
        }

        mnl_socket_close(nl);
    }
    else {
        perror("mnl_socket_open");
    }

    return NULL;
}


void nl_cb(EV_P_ ev_io *w, int revents)
{
    struct mnl_socket *nl = w->data;

    receive_nl_msg(nl);
}


void timeout_cb(EV_P_ ev_timer *w, int revents)
{
    struct mnl_socket *nl = w->data;

    ev_timer_stop(EV_A_ w);
    request_addr_dump(nl);
}


void stop_cb(EV_P_ ev_signal *w, int revents)
{
    ev_break(EV_A_ EVBREAK_ALL);
}


int validate_interface_config(cfg_t *cfg, cfg_opt_t *opt)
{
    int ret = CFG_SUCCESS;

    // get the last parsed interface section
    cfg_t *sec = cfg_opt_getnsec(opt, cfg_opt_size(opt) - 1);

    // all sub-options are mandatory
    for (cfg_opt_t *subopt = opt->subopts; subopt->type != CFGT_NONE; subopt++) {
        if (cfg_size(sec, subopt->name) < 1) {
            cfg_error(cfg, "Missing %s in interface section", subopt->name);
            ret = CFG_PARSE_ERROR;
        }
    }

    return ret;
}


cfg_t *read_config(const char *cfgfile)
{
    cfg_opt_t interface_opts[] = {
        CFG_STR("url", 0, CFGF_NODEFAULT),
        CFG_STR("login", 0, CFGF_NODEFAULT),
        CFG_STR("password", 0, CFGF_NODEFAULT),
        CFG_STR("domain", 0, CFGF_NODEFAULT),
        CFG_END()
    };

    cfg_opt_t opts[] = {
        CFG_SEC("interface", interface_opts, CFGF_MULTI | CFGF_TITLE | CFGF_NO_TITLE_DUPES),
        CFG_END()
    };

    cfg_t *cfg = cfg_init(opts, CFGF_NONE);
    cfg_set_validate_func(cfg, "interface", validate_interface_config);

    switch (cfg_parse(cfg, cfgfile)) {
    case CFG_SUCCESS:
        return cfg;
    case CFG_FILE_ERROR:
        perror(cfgfile);
        break;
    }

    cfg_free(cfg);
    return NULL;
}


int main(int argc, char *argv[])
{
    int opt;
    const char *cfgfile = DEFAULT_CONF_FILE;
    int ret = EXIT_FAILURE;
    struct mnl_socket *nl;
    struct ev_loop *loop = EV_DEFAULT;

    // parse command line
    const struct option options[] = {
        { "help",    no_argument,       0, 'h' },
        { "version", no_argument,       0, 'v' },
        { "config",  required_argument, 0, 'c' },
        { 0,         0,                 0,  0  },
    };

    while ((opt = getopt_long(argc, argv, "hvc:", options, NULL)) != -1) {
        switch (opt) {
        case 'c':
            cfgfile = optarg;
            break;
        case 'h':
            help();
            return EXIT_SUCCESS;
        case 'v':
            version();
            return EXIT_SUCCESS;
        default:
            syntax();
            return EXIT_FAILURE;
        }
    }

    // read configuration
    if ((config = read_config(cfgfile)) != NULL) {
        // open netlink
        if ((nl = nl_open()) != NULL) {
            // init event loop
            ev_io_init(&nl_watcher, nl_cb, mnl_socket_get_fd(nl), EV_READ);
            nl_watcher.data = nl;
            ev_io_start(loop, &nl_watcher);

            ev_timer_init(&addr_timeout_watcher, timeout_cb, 0.0, 2.0);
            addr_timeout_watcher.data = nl;
            ev_timer_start(loop, &addr_timeout_watcher);

            ev_signal_init(&stop_watcher, stop_cb, SIGTERM);
            ev_signal_start(loop, &stop_watcher);

            ev_run(loop, 0);
            ret = EXIT_SUCCESS;

            mnl_socket_close(nl);
        }
    }

    return ret;
}
