#include "thrasher.h"

extern int      rbl_queries;
extern int      rbl_max_queries;
extern uint32_t rbl_negcache_timeout;
extern GTree   *rbl_negative_cache;
extern char    *rbl_zone;
extern int      syslog_enabled;
extern FILE    *logfile;

void
expire_rbl_negcache(int sock, short which, rbl_negcache_t * rnode)
{
#ifdef DEBUG
    LOG(logfile, "Expiring negative RBL cache for %u", rnode->addr);
#endif

    if (!rnode)
        return;

    evtimer_del(&rnode->timeout);
    g_tree_remove(rbl_negative_cache, &rnode->addr);
    free(rnode);
}

void
get_rbl_answer(int result, char type, int count, int ttl,
               struct in_addr *addresses, uint32_t * arg)
{
    uint32_t        addr;
    qstats_t        qsnode;
    client_conn_t   cconn;
    struct in_addr *in_addrs;
#ifdef DEBUG
    LOG(logfile, "Got an answer for address %u", arg ? *arg : 0);
#endif

    if (!arg)
        return;

    addr = *arg;
    in_addrs = NULL;

    free(arg);

    rbl_queries -= 1;

    if (result != DNS_ERR_NONE || count <= 0 ||
        type != DNS_IPv4_A || ttl < 0) {
        /*
         * we must cache the negative answer so we don't kill our rbl
         * server 
         */
        rbl_negcache_t *rnode;
        struct timeval  tv;

        if (result != DNS_ERR_NOTEXIST)
            return;

        rnode = malloc(sizeof(rbl_negcache_t));
        rnode->addr = addr;

        tv.tv_sec = rbl_negcache_timeout;
        tv.tv_usec = 0;

        evtimer_set(&rnode->timeout, (void *) expire_rbl_negcache, rnode);
        evtimer_add(&rnode->timeout, &tv);

        g_tree_insert(rbl_negative_cache, &rnode->addr, rnode);

        return;
    }

    /*
     * insert the entry into our holddown list 
     */
#ifdef DEBUG
    LOG(logfile, "RBL Server thinks %u is bad! BADBOY!", htonl(addr));
#endif
    qsnode.saddr = htonl(addr);

    if (in_addrs) {
        cconn.conn_addr = (uint32_t) in_addrs[0].s_addr;
        block_addr(&cconn, qsnode.saddr, "rbl");
    } else
        block_addr(NULL, qsnode.saddr, "rbl");

    LOG(logfile, "holding down address %s triggered by RBL",
        inet_ntoa(*(struct in_addr *) &qsnode.saddr));

}

void
make_rbl_query(uint32_t addr)
{
    char           *query;
    char           *addr_str;
    uint32_t       *addrarg;
    int             name_sz;

    addr = htonl(addr);

    if (g_tree_lookup(rbl_negative_cache, &addr)) {
#if DEBUG
        LOG(logfile, "addr %u already in negative cache, not querying rbl",
            addr);
#endif
        return;
    }

    if ((rbl_max_queries) && rbl_queries >= rbl_max_queries) {
#if DEBUG
        LOG(logfile,
            "Cannot send query, RBL queue filled to the brim! (%u)", addr);
#endif
        return;
    }

    addr_str = inet_ntoa(*(struct in_addr *) &addr);

    if (!addr_str)
        return;

    name_sz = strlen(addr_str) + strlen(rbl_zone) + 4;

    if (!(query = malloc(name_sz))) {
        LOG(logfile, "Cannot allocate memory: %s", strerror(errno));
        exit(1);
    }

    snprintf(query, name_sz - 1, "%s.%s", addr_str, rbl_zone);

#if DEBUG
    LOG(logfile, "Making RBL Request for %s", query);
#endif

    if (!(addrarg = malloc(sizeof(uint32_t)))) {
        LOG(logfile, "Cannot allocate memory: %s", strerror(errno));
        exit(1);
    }

    memcpy(addrarg, &addr, sizeof(uint32_t));

    rbl_queries += 1;
    evdns_resolve_ipv4(query, 0,
                       (void *) get_rbl_answer, (void *) addrarg);

    free(query);
}
