#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <curl/curl.h>

#include "net.h"


#define NLDDCD_USERAGENT  "nlddcd/1.0"
#define MIN(a, b)  (((a) < (b)) ? (a) : (b))


typedef struct {
    char data[256];
    size_t length;
} response_t;


static size_t curl_recv_cb(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    response_t *response = userdata;
    size_t bytes_avail = size * nmemb;
    size_t bytes_free = sizeof response->data - response->length - 1;
    size_t bytes_to_copy = MIN(bytes_avail, bytes_free);

    memcpy(response->data + response->length, ptr, bytes_to_copy);
    response->length += bytes_to_copy;

    return bytes_avail;
}


static void print_curl_error(CURLcode res, const char *errorbuffer)
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


bool init_net(void)
{
    return curl_global_init(CURL_GLOBAL_DEFAULT) == CURLE_OK;
}


void cleanup_net(void)
{
    curl_global_cleanup();
}
