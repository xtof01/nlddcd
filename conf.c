#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#include <confuse.h>
#include <ev.h>

#include "conf.h"

extern void timeout_cb(EV_P_ ev_timer *w, int revents);

static cfg_t *config;


static int validate_interface_config(cfg_t *cfg, cfg_opt_t *opt)
{
    int ret = CFG_SUCCESS;

    // get the last parsed interface section
    cfg_t *sec = cfg_opt_getnsec(opt, cfg_opt_size(opt) - 1);

    // all sub-options are mandatory
    for (cfg_opt_t *subopt = opt->subopts; subopt->type != CFGT_NONE; subopt++) {
        if (cfg_size(sec, cfg_opt_name(subopt)) < 1) {
            cfg_error(cfg, "Missing %s in interface section", cfg_opt_name(subopt));
            ret = CFG_PARSE_ERROR;
        }
    }

    return ret;
}


static cfg_t *parse_config(const char *cfgfile)
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


static void prepare_interface_status(interface_status_t **if_stat_head)
{
    unsigned int i, num_interfaces;
    interface_status_t *if_stat;

    *if_stat_head = NULL;
    num_interfaces = cfg_size(config, "interface");

    for (i = 0; i < num_interfaces; i++) {
        if_stat = calloc(sizeof *if_stat, 1);

        ev_timer_init(&if_stat->timeout, timeout_cb, 0.0, 5.0);

        cfg_t *interface = cfg_getnsec(config, "interface", i);
        if_stat->ifname = cfg_title(interface);
        if_stat->url = cfg_getstr(interface, "url");
        if_stat->login = cfg_getstr(interface, "login");
        if_stat->password = cfg_getstr(interface, "password");
        if_stat->domain = cfg_getstr(interface, "domain");

        if_stat->next = *if_stat_head;
        *if_stat_head = if_stat;
    }
}


bool read_config(const char *cfgfile, interface_status_t **if_stat_head)
{
    config = parse_config(cfgfile);

    if (config != NULL) {
        prepare_interface_status(if_stat_head);
        return true;
    }

    return false;
}


void cleanup_config(void)
{
    cfg_free(config);
}
