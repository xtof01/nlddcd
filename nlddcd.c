#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <limits.h>
#include <ctype.h>
#include <getopt.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <linux/rtnetlink.h>
#include <libmnl/libmnl.h>
#include <curl/curl.h>
#include <ev.h>

#include "conf.h"


#define DEFAULT_CONF_FILE SYSCONFDIR "/nlddcd.conf"
#define NLDDCD_USERAGENT  "nlddcd/1.0"

#define MIN(a, b)  (((a) < (b)) ? (a) : (b))

#define container_of(ptr, type, member) ({                      \
        const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
        (type *)( (char *)__mptr - offsetof(type, member) );})


typedef struct {
    char data[256];
    size_t length;
} response_t;


interface_status_t *if_stat_head;
ev_io nl_watcher;
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


size_t curl_recv_cb(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    response_t *response = userdata;
    size_t bytes_avail = size * nmemb;
    size_t bytes_free = sizeof response->data - response->length - 1;
    size_t bytes_to_copy = MIN(bytes_avail, bytes_free);

    memcpy(response->data + response->length, ptr, bytes_to_copy);
    response->length += bytes_to_copy;

    return bytes_avail;
}


void print_curl_error(CURLcode res, const char *errorbuffer)
{
    size_t len = strlen(errorbuffer);

    fprintf(stderr, "error: (%d) ", res);
    if (len > 0) {
        fprintf(stderr, "%s%s", errorbuffer,
                ((errorbuffer[len - 1] != '\n') ? "\n" : ""));
    }
    else {
        fprintf(stderr, "%s\n", curl_easy_strerror(res));
    }
}


void perform_ddns_update(interface_status_t *if_stat)
{
    CURL *curl;
    char ipaddrstr[INET_ADDRSTRLEN];
    char ip6addrstr[INET6_ADDRSTRLEN];
    size_t urllen = strlen(if_stat->url) + strlen(if_stat->domain) + 128;
    char *urlbuffer = malloc(urllen);
    char *errorbuffer = malloc(CURL_ERROR_SIZE);
    response_t *response = malloc(sizeof *response);

    int n_addrs = 0;

    if (if_stat->local_ipaddr_set) {
        inet_ntop(AF_INET, &if_stat->local_ipaddr, ipaddrstr, sizeof ipaddrstr);
        n_addrs++;
    }
    if (if_stat->local_ip6addr_set) {
        inet_ntop(AF_INET6, &if_stat->local_ip6addr, ip6addrstr, sizeof ip6addrstr);
        n_addrs++;
    }

    // build request URL
    snprintf(urlbuffer, urllen, "%s?hostname=%s&myip=%s%s%s",
             if_stat->url, if_stat->domain,
             if_stat->local_ipaddr_set ? ipaddrstr : "",
             n_addrs > 1 ? "," : "",
             if_stat->local_ip6addr_set ? ip6addrstr : "");

    //printf("URL: %s\n", urlbuffer);

    if ((curl = curl_easy_init()) != NULL) {
        CURLcode res;

        curl_easy_setopt(curl, CURLOPT_URL, urlbuffer);
        curl_easy_setopt(curl, CURLOPT_USERAGENT, NLDDCD_USERAGENT);
        curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
        curl_easy_setopt(curl, CURLOPT_USERNAME, if_stat->login);
        curl_easy_setopt(curl, CURLOPT_PASSWORD, if_stat->password);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_recv_cb);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, response);
        curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errorbuffer);

        errorbuffer[0] = 0;
        response->length = 0;

        // perform HTTP request
        res = curl_easy_perform(curl);
        if (res == CURLE_OK) {
            response->data[response->length] = 0;
            printf("response: %s\n", response->data);

            for (size_t i = 0; i < response->length; i++) {
                if (!isalnum(response->data[i])) {
                    response->data[i] = 0;
                    break;
                }
            }

            // check response
            if (strcmp(response->data, "good") == 0 ||
                strcmp(response->data, "nochg") == 0) {
                printf("Update succeeded\n");
                if (if_stat->local_ipaddr_set) {
                    if_stat->dns_ipaddr = if_stat->local_ipaddr;
                }
                if_stat->dns_ipaddr_set = if_stat->local_ipaddr_set;
                if (if_stat->local_ip6addr_set) {
                    if_stat->dns_ip6addr = if_stat->local_ip6addr;
                }
                if_stat->dns_ip6addr_set = if_stat->local_ip6addr_set;
            }
            else {
                printf("Update failed\n");
            }
        }
        else {
            print_curl_error(res, errorbuffer);
        }
        curl_easy_cleanup(curl);
    }

    free(response);
    free(errorbuffer);
    free(urlbuffer);
}


void resolve_domain(interface_status_t *if_stat)
{
    struct addrinfo hints, *result, *addr;
    int ret;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;

    // try to get A and AAAA records of domain
    ret = getaddrinfo(if_stat->domain, NULL, &hints, &result);
    if (ret == 0) {
        if_stat->dns_ipaddr_set = false;
        if_stat->dns_ip6addr_set = false;

        for (addr = result; addr != NULL; addr = addr->ai_next) {
            switch (addr->ai_family) {
            case AF_INET:
                if_stat->dns_ipaddr = ((struct sockaddr_in *)addr->ai_addr)->sin_addr;
                if_stat->dns_ipaddr_set = true;
                break;
            case AF_INET6:
                if_stat->dns_ip6addr = ((struct sockaddr_in6 *)addr->ai_addr)->sin6_addr;
                if_stat->dns_ip6addr_set = true;
                break;
            }
        }

        if_stat->resolved = true;

        freeaddrinfo(result);
    }
    else {
        fprintf(stderr, "%s: %s\n", if_stat->domain, gai_strerror(ret));
    }
}


void timeout_cb(EV_P_ ev_timer *w, int revents)
{
    bool update_required = false;
    interface_status_t *if_stat = container_of(w, interface_status_t, timeout);

    ev_timer_stop(EV_A_ w);

    if (!if_stat->resolved) {
        resolve_domain(if_stat);
    }

    // compare local and remote addresses
    if ((if_stat->local_ipaddr_set != if_stat->dns_ipaddr_set) ||
        (if_stat->local_ipaddr_set == true && /*if_stat->dns_ipaddr_set == true &&*/
         if_stat->local_ipaddr.s_addr != if_stat->dns_ipaddr.s_addr)) {
        printf("IPv4 address of interface %s differs from address of %s\n",
               if_stat->ifname, if_stat->domain);
        update_required = true;
    }
    if ((if_stat->local_ip6addr_set != if_stat->dns_ip6addr_set) ||
        (if_stat->local_ip6addr_set == true && /*if_stat->dns_ip6addr_set == true &&*/
         memcmp(if_stat->local_ip6addr.s6_addr, if_stat->dns_ip6addr.s6_addr, 16) != 0)) {
        printf("IPv6 address of interface %s differs from address of %s\n",
               if_stat->ifname, if_stat->domain);
        update_required = true;
    }

    if (update_required) {
        if (if_stat->local_ipaddr_set || if_stat->local_ip6addr_set) {
            perform_ddns_update(if_stat);
        }
        else {
            printf("No addresses configured on interface %s, skipping update\n",
                   if_stat->ifname);
        }
    }
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


void parse_addr_msg(const struct nlmsghdr *nlh)
{
    char ifname[IF_NAMESIZE];
    char addrstr[INET6_ADDRSTRLEN];
    unsigned int flags;
    const void *addr = NULL;
    const struct nlattr *attr;
    const struct ifaddrmsg *ifa = mnl_nlmsg_get_payload(nlh);
    size_t addrsize = af_addr_size(ifa->ifa_family);

    if_indextoname(ifa->ifa_index, ifname);
    flags = ifa->ifa_flags;

    mnl_attr_for_each(attr, nlh, sizeof *ifa) {
        if (mnl_attr_type_valid(attr, RTA_MAX) > 0) {
            int type = mnl_attr_get_type(attr);

            if (type == IFA_LOCAL) {
                if (mnl_attr_validate2(attr, MNL_TYPE_BINARY, addrsize) >= 0) {
                    addr = mnl_attr_get_payload(attr);
                }
            }
            if (type == IFA_ADDRESS && addr == NULL) {
                if (mnl_attr_validate2(attr, MNL_TYPE_BINARY, addrsize) >= 0) {
                    addr = mnl_attr_get_payload(attr);
                }
            }
            if (type == IFA_FLAGS) {
                if (mnl_attr_validate(attr, MNL_TYPE_U32) >= 0) {
                    flags = mnl_attr_get_u32(attr);
                }
            }
        }
    }

    // found non-temporary global address?
    if (addr != NULL && ifa->ifa_scope == RT_SCOPE_UNIVERSE && (flags & IFA_F_TEMPORARY) == 0) {
        interface_status_t *if_stat;

        for (if_stat = if_stat_head; if_stat != NULL; if_stat = if_stat->next) {
            if (strncmp(if_stat->ifname, ifname, IF_NAMESIZE) == 0) {
                void *local_addr = NULL;
                bool *local_addr_set = NULL;

                switch (ifa->ifa_family) {
                case AF_INET:
                    local_addr = &if_stat->local_ipaddr;
                    local_addr_set = &if_stat->local_ipaddr_set;
                    break;
                case AF_INET6:
                    local_addr = &if_stat->local_ip6addr;
                    local_addr_set = &if_stat->local_ip6addr_set;
                    break;
                default:
                    continue;
                }

                switch (nlh->nlmsg_type) {
                case RTM_NEWADDR:
                    if (!*local_addr_set || memcmp(local_addr, addr, addrsize) != 0) {

                        printf("detected address change on %s: %s\n",
                               ifname, inet_ntop(ifa->ifa_family, addr, addrstr, sizeof addrstr));
                        memcpy(local_addr, addr, addrsize);
                        *local_addr_set = true;

                        ev_timer_again(EV_DEFAULT_ &if_stat->timeout);
                    }
                    break;

                case RTM_DELADDR:
                    if (*local_addr_set && memcmp(local_addr, addr, addrsize) == 0) {
                        printf("address removed from %s: %s\n",
                               ifname, inet_ntop(ifa->ifa_family, addr, addrstr, sizeof addrstr));
                        memset(local_addr, 0, addrsize);
                        *local_addr_set = false;

                        ev_timer_again(EV_DEFAULT_ &if_stat->timeout);
                    }
                    break;
                }
            }
        }
    }
}


int nl_msg_cb(const struct nlmsghdr *nlh, void *data)
{
    switch (nlh->nlmsg_type) {
    case RTM_NEWADDR:
    case RTM_DELADDR:
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
    rt->rtgen_family = AF_UNSPEC;

    if (mnl_socket_sendto(nl, buf, nlh->nlmsg_len) < 0) {
        perror("mnl_socket_sendto");
    }
}


int join_mcast_groups(struct mnl_socket *nl)
{
    int groups[] = {
        RTNLGRP_IPV4_IFADDR,
        RTNLGRP_IPV6_IFADDR,
    };
    int ret = 0;

    for (size_t i = 0; i < MNL_ARRAY_SIZE(groups) && ret == 0; i++) {
        ret = mnl_socket_setsockopt(nl, NETLINK_ADD_MEMBERSHIP,
                                    &groups[i], sizeof groups[i]);
    }
    return ret;
}


struct mnl_socket *nl_open()
{
    struct mnl_socket *nl;

    nl = mnl_socket_open(NETLINK_ROUTE);
    if (nl != NULL) {
        int fd = mnl_socket_get_fd(nl);

        if (fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK) == 0) {

            if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) == 0) {
                portid = mnl_socket_get_portid(nl);
                seq = time(NULL);

                if (join_mcast_groups(nl) == 0) {
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


void stop_cb(EV_P_ ev_signal *w, int revents)
{
    ev_break(EV_A_ EVBREAK_ALL);
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

    if (curl_global_init(CURL_GLOBAL_DEFAULT) == CURLE_OK) {
        // read configuration
        if (read_config(cfgfile, &if_stat_head)) {

            // open netlink
            if ((nl = nl_open()) != NULL) {
                // init event loop
                ev_io_init(&nl_watcher, nl_cb, mnl_socket_get_fd(nl), EV_READ);
                nl_watcher.data = nl;
                ev_io_start(loop, &nl_watcher);

                ev_signal_init(&stop_watcher, stop_cb, SIGTERM);
                ev_signal_start(loop, &stop_watcher);

                // request initial address dump
                request_addr_dump(nl);

                ev_run(loop, 0);
                ret = EXIT_SUCCESS;

                mnl_socket_close(nl);
            }

            cleanup_config();
        }

        curl_global_cleanup();
    }

    return ret;
}
