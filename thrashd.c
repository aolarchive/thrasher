#include "thrasher.h"
#include "version.h"

#define MAX_URI_SIZE 255
#define MAX_HOST_SIZE 255

static char    *process_name;
static uint32_t uri_check;
static uint32_t site_check;
static uint32_t addr_check;
static char    *bind_addr;
static uint16_t bind_port;
static uint32_t soft_block_timeout;
static block_ratio_t site_ratio;
static block_ratio_t uri_ratio;
static block_ratio_t addr_ratio;
struct event    server_event;
static int      server_port;
static uint32_t qps;
static uint32_t qps_last;
struct event    qps_event;
static int      rundaemon;
static int      syslog_enabled;
static char    *rbl_zone;
static char    *rbl_ns;
static int      rbl_limit;
static int      rbl_max_queries;
static int      rbl_queries;
static uint32_t rbl_negcache_timeout;
static uint64_t total_blocked_connections;
GSList         *current_connections;
GTree          *current_blocks;
GHashTable     *uri_table;
GHashTable     *host_table;
GHashTable     *addr_table;
GTree          *rbl_negative_cache;
GHashTable     *uri_states;
GHashTable     *host_states;

void
reset_query(query_t * query)
{
    if (query->uri)
        free(query->uri);
    if (query->host)
        free(query->host);

    query->uri = NULL;
    query->host = NULL;
    query->uri_len = 0;
    query->host_len = 0;
}

void
free_client_conn(client_conn_t * conn)
{
    reset_iov(&conn->data);
    reset_query(&conn->query);

    current_connections =
        g_slist_remove(current_connections, (gconstpointer) conn);

    free(conn);
}


int
uint32_cmp(const void *a, const void *b)
{
    if (*(uint32_t *) a < *(uint32_t *) b)
        return -1;

    if (*(uint32_t *) a > *(uint32_t *) b)
        return 1;

    return 0;
}

void
globals_init(void)
{
    uri_check                  = 1;
    site_check                 = 1;
    addr_check                 = 1;
    bind_addr                  = "0.0.0.0";
    bind_port                  = 1972;
    server_port                = 1979;
    soft_block_timeout         = 60;
    site_ratio.num_connections = 10;
    uri_ratio.num_connections  = 10;
    site_ratio.timelimit       = 60;
    uri_ratio.timelimit        = 60;
    addr_ratio.num_connections = 100;
    addr_ratio.timelimit       = 10;
    qps                        = 0;
    qps_last                   = 0;
    current_connections        = g_slist_alloc();
    current_blocks             = g_tree_new((GCompareFunc) uint32_cmp);
    uri_table                  = g_hash_table_new(g_str_hash, g_str_equal);
    host_table                 = g_hash_table_new(g_str_hash, g_str_equal);
    addr_table                 = g_hash_table_new(g_str_hash, g_str_equal);
    process_name               = "default";
    syslog_enabled             = 1;
    rundaemon                  = 0;
    rbl_zone                   = NULL;
    rbl_negative_cache         = g_tree_new((GCompareFunc) uint32_cmp);
    rbl_negcache_timeout       = 10;
    rbl_limit                  = 0;
    rbl_max_queries            = 0;
    rbl_queries                = 0;
    total_blocked_connections  = 0;
}

int
set_nb(int sock)
{
    return fcntl(sock, F_SETFL, fcntl(sock, F_GETFL, 0) | O_NONBLOCK);
}

void
expire_rbl_negcache(int sock, short which, rbl_negcache_t * rnode)
{
#ifdef DEBUG
    LOG("Expiring negative RBL cache for %u", rnode->addr);
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
    struct in_addr  *in_addrs;
#ifdef DEBUG
    LOG("Got an answer for address %u", arg ? *arg : 0);
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
    LOG("RBL Server thinks %u is bad! BADBOY!", htonl(addr));
#endif
    qsnode.saddr = htonl(addr);

    if(in_addrs)
    {
	cconn.conn_addr = (uint32_t)in_addrs[0].s_addr; 
	block_addr(&cconn, &qsnode);
    }
    else
	block_addr(NULL, &qsnode);

    LOG("holding down address %s triggered by RBL", 
	    inet_ntoa(*(struct in_addr *)&qsnode.saddr));
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
        LOG("addr %u already in negative cache, not querying rbl", addr);
#endif
        return;
    }

    if ((rbl_max_queries) && rbl_queries >= rbl_max_queries)
    {
#if DEBUG
	LOG("Cannot send query, RBL queue filled to the brim! (%u)", addr);
#endif
	return;
    }

    addr_str = inet_ntoa(*(struct in_addr *) &addr);

    if (!addr_str)
        return;

    name_sz = strlen(addr_str) + strlen(rbl_zone) + 4;

    if (!(query = malloc(name_sz))) {
        LOG("Cannot allocate memory: %s", strerror(errno));
        exit(1);
    }

    snprintf(query, name_sz - 1, "%s.%s", addr_str, rbl_zone);

#if DEBUG
    LOG("Making RBL Request for %s", query);
#endif

    if (!(addrarg = malloc(sizeof(uint32_t)))) {
        LOG("Cannot allocate memory: %s", strerror(errno));
        exit(1);
    }

    memcpy(addrarg, &addr, sizeof(uint32_t));

    rbl_queries += 1;
    evdns_resolve_ipv4(query,
                       0, (void *) get_rbl_answer, (void *) addrarg);


    free(query);
}


void
remove_holddown(uint32_t addr)
{
    g_tree_remove(current_blocks, &addr);
}

void
expire_bnode(int sock, short which, blocked_node_t * bnode)
{
    /*
     * blocked node expiration 
     */
    LOG("expired address %s",
        inet_ntoa(*(struct in_addr *) &bnode->saddr));

    evtimer_del(&bnode->timeout);
    remove_holddown(bnode->saddr);
    free(bnode);
}

void
expire_stats_node(int sock, short which, qstats_t * stat_node)
{
#ifdef DEBUG
    LOG("expire_stats_node(%p) key:%s table:%p", stat_node,
        stat_node->key, stat_node->table);
#endif

    /*
     * remove the timers 
     */
    evtimer_del(&stat_node->timeout);

    /*
     * remove this entry from the designated hash table 
     */
    g_hash_table_remove(stat_node->table, stat_node->key);

    free(stat_node->key);
    free(stat_node);
}

blocked_node_t *
block_addr(client_conn_t * conn, qstats_t * stats)
{
    blocked_node_t *bnode;
    struct timeval  tv;

    /*
     * create a new blocked node structure 
     */
    if (!(bnode = malloc(sizeof(blocked_node_t)))) {
        LOG("Out of memory: %s", strerror(errno));
        exit(1);
    }

    memset(bnode, 0, sizeof(blocked_node_t));

    bnode->saddr = stats->saddr;
    bnode->count = 1;

    if (conn)
        bnode->first_seen_addr = conn->conn_addr;
    else
        /*
         * sometimes we don't get a conn struct, this can be due to other 
         * types of blocking - RBL for example 
         */
        bnode->first_seen_addr = 0;

    /*
     * insert the blocked node into our tree of held down addresses 
     */
    g_tree_insert(current_blocks, &bnode->saddr, bnode);

    /*
     * add our soft timeout for this node 
     */
    tv.tv_sec = soft_block_timeout;
    tv.tv_usec = 0;

    evtimer_set(&bnode->timeout, (void *) expire_bnode, bnode);
    evtimer_add(&bnode->timeout, &tv);

    return bnode;
}

int
update_thresholds(client_conn_t * conn, char *key, stat_type_t type)
{
    GHashTable     *table;
    static block_ratio_t *ratio;
    qstats_t       *stats;
    struct timeval  tv;

    switch (type) {
    case stat_type_uri:
        table = uri_table;
        ratio = &uri_ratio;
        break;
    case stat_type_host:
        table = host_table;
        ratio = &site_ratio;
        break;
    case stat_type_address:
	table = addr_table;
	ratio = &addr_ratio;
	break;
    default:
        return 0;
    }

    stats = g_hash_table_lookup(table, key);

    if (!stats) {
        /*
         * create a new statistics table for this type 
         */

        if (!(stats = malloc(sizeof(qstats_t)))) {
            LOG("Out of memory: %s", strerror(errno));
            exit(1);
        }

        stats->connections = 0;
        stats->saddr = conn->query.saddr;
        stats->key = strdup(key);
        stats->table = table;

        /*
         * insert the new statistics table into its hash 
         */
        g_hash_table_insert(table, stats->key, stats);

        /*
         * now set an expire timer for this qstat_t node 
         */
        tv.tv_sec = ratio->timelimit;
        tv.tv_usec = 0;

        evtimer_set(&stats->timeout, (void *) expire_stats_node, stats);
        evtimer_add(&stats->timeout, &tv);

    }
#ifdef DEBUG
    LOG("Our stats node is %p (key: %s, table:%p saddr:%u)", stats,
        stats->key, stats->table, stats->saddr);
#endif

    /*
     * increment our connection counter 
     */
    stats->connections++;

    if (stats->connections >= ratio->num_connections) {
        /*
         * we seemed to have hit a threshold 
         */
        blocked_node_t *bnode;
        char           *blockedaddr;
        char           *triggeraddr;

        bnode = block_addr(conn, stats);

        blockedaddr = strdup(inet_ntoa(*(struct in_addr *) &bnode->saddr));
        triggeraddr =
            strdup(inet_ntoa(*(struct in_addr *) &bnode->first_seen_addr));

        LOG("holding down address %s triggered by %s",
            blockedaddr, triggeraddr);

        free(blockedaddr);
        free(triggeraddr);

	expire_stats_node(0, 0, stats);

        return 1;
    }

    return 0;
}

int
do_thresholding(client_conn_t * conn)
{
    uint32_t        hkeylen,
                    ukeylen;
    char           *hkey,
                   *ukey;
    int             blocked;
    blocked_node_t *bnode;

    qps += 1;
    blocked = 0;
    ukey = NULL;
    hkey = NULL;

    /*
     * first check if we already have a block somewhere 
     */
    if ((bnode = g_tree_lookup(current_blocks, &conn->query.saddr))) {
        /*
         * this connection seems to be blocked, reset our block timers
         * and continue on 
         */
        struct timeval  tv;
        tv.tv_sec = soft_block_timeout;
        tv.tv_usec = 0;

        evtimer_del(&bnode->timeout);
        evtimer_set(&bnode->timeout, (void *) expire_bnode, bnode);
        evtimer_add(&bnode->timeout, &tv);

        /*
         * increment our stats counter 
         */
        bnode->count++;
	total_blocked_connections++;
        return 1;
    }

    /*
     * we are currently not blocked 
     */

    /*
     * next we query our RBL server if applicable. NOTE: this will not
     * block immediately, this is a post check. This is so that we don't
     * block on the operation 
     */

    if (rbl_zone)
        make_rbl_query(conn->query.saddr);

    switch(conn->type)
    {
	case TYPE_THRESHOLD_v1:
	    ukeylen = conn->query.uri_len + 13;

	    if (!(ukey = calloc(ukeylen, 1))) {
		LOG("Out of memory: %s", strerror(errno));
		exit(1);
	    }

	    hkeylen = conn->query.host_len + 13;
    
	    if (!(hkey = calloc(hkeylen, 1))) {
		LOG("Out of memory: %s", strerror(errno));
		exit(1);
	    }

	    snprintf(ukey, ukeylen - 1, "%u%s", conn->query.saddr,
		    conn->query.uri);
    
	    snprintf(hkey, hkeylen - 1, "%u%s", conn->query.saddr,
		    conn->query.host);

	    if (uri_check && update_thresholds(conn, ukey, 
			stat_type_uri))
		blocked = 1;

	    if (site_check && update_thresholds(conn, hkey, 
			stat_type_host))
		blocked = 1;
		
	    break;
	case TYPE_THRESHOLD_v2:
	    /* with v2 we only care about the source-address */

	    if (addr_check <= 0)
	    {
		printf("FUCK %d\n", addr_check); 
		break;
	    }

	    hkeylen = 13;

	    if (!(hkey = calloc(hkeylen, 1)))
	    {
		LOG("Out of memory: %s", strerror(errno));
		exit(1);
	    }

	    snprintf(hkey, hkeylen - 1, "%u", conn->query.saddr);

	    if (update_thresholds(conn, hkey, stat_type_address))
		blocked = 1;

	    break;
	default:
	    blocked = 0;
	    break;
    }

    if (ukey)
	free(ukey);
    if (hkey)
	free(hkey);

    return blocked;
}

void
client_process_data(int sock, short which, client_conn_t * conn)
{
    int             ioret;

    if (!conn->data.buf)
        initialize_iov(&conn->data, 1);

    if (do_thresholding(conn))
        *conn->data.buf = 1;
    else
        *conn->data.buf = 0;

    ioret = write_iov(&conn->data, sock);

    if (ioret < 0) {
        free_client_conn(conn);
        close(sock);
        return;
    }

    if (ioret > 0) {
        event_set(&conn->event, sock, EV_WRITE,
                  (void *) client_process_data, conn);
        event_add(&conn->event, 0);
        return;
    }

    reset_iov(&conn->data);
    reset_query(&conn->query);

    /*
     * we've done all our work on this, go back to the beginning 
     */
    event_set(&conn->event, sock, EV_READ,
              (void *) client_read_type, conn);
    event_add(&conn->event, 0);
}

void
client_read_payload(int sock, short which, client_conn_t * conn)
{
    int             ioret;

    if (!conn->data.buf)
        initialize_iov(&conn->data,
                       conn->query.uri_len + conn->query.host_len);

    ioret = read_iov(&conn->data, sock);

    if (ioret < 0) {
        free_client_conn(conn);
        close(sock);
        return;
    }

    if (ioret > 0) {
        event_set(&conn->event, sock, EV_READ,
                  (void *) client_read_payload, conn);
        event_add(&conn->event, 0);
        return;
    }

    conn->query.uri = calloc(conn->query.uri_len + 1, 1);

    if (!conn->query.uri) {
        LOG("Out of memory: %s", strerror(errno));
        exit(1);
    }

    conn->query.host = calloc(conn->query.host_len + 1, 1);

    if (!conn->query.host) {
        LOG("Out of memory: %s", strerror(errno));
        exit(1);
    }

    memcpy(conn->query.uri, conn->data.buf, conn->query.uri_len);

    memcpy(conn->query.host,
           &conn->data.buf[conn->query.uri_len], conn->query.host_len);

    reset_iov(&conn->data);

#ifdef DEBUG
    LOG("host: '%s' uri: '%s'", conn->query.host, conn->query.uri);
#endif

    event_set(&conn->event, sock, EV_WRITE,
              (void *) client_process_data, conn);
    event_add(&conn->event, 0);

}

void 
client_read_v2_header(int sock, short which, client_conn_t * conn)
{
    int      ioret;
    uint32_t saddr;

    if (!conn->data.buf)
	initialize_iov(&conn->data, 4);

    ioret = read_iov(&conn->data, sock);

    if (ioret < 0)
    {
	free_client_conn(conn);
	close(sock);
	return;
    }

    if (ioret > 0)
    {
	event_set(&conn->event, sock, EV_READ,
		(void *) client_read_v2_header, conn);
	event_add(&conn->event, 0);
	return;
    }

    memcpy(&saddr, conn->data.buf, sizeof(uint32_t));
    conn->query.saddr = saddr;
    reset_iov(&conn->data);

    /* v2 allows us to just recv a source address,
       thus we can go directly into processing the
       data */
    event_set(&conn->event, sock, EV_WRITE,
	    (void *) client_process_data, conn); 
    event_add(&conn->event, 0);
}

void
client_read_v1_header(int sock, short which, client_conn_t * conn)
{
    int             ioret;
    uint32_t        saddr;
    uint16_t        urilen;
    uint16_t        hostlen;

    if (!conn->data.buf)
        initialize_iov(&conn->data, 8);

    ioret = read_iov(&conn->data, sock);

    if (ioret < 0) {
        free_client_conn(conn);
        close(sock);
        return;
    }

    if (ioret > 0) {
        event_set(&conn->event, sock, EV_READ,
                  (void *) client_read_v1_header, conn);
        event_add(&conn->event, 0);
        return;
    }

    memcpy(&saddr, &conn->data.buf[0], sizeof(uint32_t));
    memcpy(&urilen, &conn->data.buf[4], sizeof(uint16_t));
    memcpy(&hostlen, &conn->data.buf[6], sizeof(uint16_t));

    urilen = ntohs(urilen);
    hostlen = ntohs(hostlen);

    if (urilen > MAX_URI_SIZE || hostlen > MAX_HOST_SIZE ||
        urilen <= 0 || hostlen <= 0) {
        free_client_conn(conn);
        close(sock);
        return;
    }

    conn->query.uri_len = urilen;
    conn->query.host_len = hostlen;
    conn->query.saddr = saddr;
    reset_iov(&conn->data);

    event_set(&conn->event, sock, EV_READ,
              (void *) client_read_payload, conn);
    event_add(&conn->event, 0);
}

void
client_read_injection(int sock, short which, client_conn_t * conn)
{
    blocked_node_t *bnode;
    struct timeval  tv;
    uint32_t        saddr;
    int             ioret;

    if (!conn->data.buf)
        initialize_iov(&conn->data, sizeof(uint32_t));

    ioret = read_iov(&conn->data, sock);

    if (ioret < 0) {
        free_client_conn(conn);
        close(sock);
        return;
    }

    if (ioret > 0) {
        event_set(&conn->event, sock, EV_READ,
                  (void *) client_read_injection, conn);
        event_add(&conn->event, 0);
        return;
    }

    memcpy(&saddr, conn->data.buf, sizeof(uint32_t));

    switch (conn->type) {
    case TYPE_INJECT:
        /*
         * make sure the node doesn't already exist 
         */
        if ((bnode = g_tree_lookup(current_blocks, &saddr)))
	{
	    bnode->count++;
	    total_blocked_connections++;
            break;
	}

        bnode = malloc(sizeof(blocked_node_t));

        if (!bnode) {
            LOG("Out of memory: %s", strerror(errno));
            exit(1);
        }

        bnode->saddr = saddr;
        bnode->count = 0;
        bnode->first_seen_addr = 0xffffffff;

        g_tree_insert(current_blocks, &bnode->saddr, bnode);

        tv.tv_sec = soft_block_timeout;
        tv.tv_usec = 0;

        evtimer_set(&bnode->timeout, (void *) expire_bnode, bnode);
        evtimer_add(&bnode->timeout, &tv);
        break;

    case TYPE_REMOVE:
        if (!(bnode = g_tree_lookup(current_blocks, &saddr)))
            break;

        expire_bnode(0, 0, bnode);
        break;
    }


    free_client_conn(conn);
    close(sock);
    return;
}

void
client_read_type(int sock, short which, client_conn_t * conn)
{
    int             ioret;
    uint8_t         type;

    if (!conn->data.buf)
        initialize_iov(&conn->data, 1);


    ioret = read_iov(&conn->data, sock);

    if (ioret < 0) {
        free_client_conn(conn);
        close(sock);
        return;
    }

    if (ioret > 0) {
        /*
         * what? can't get 1 byte? lame 
         */
        free_client_conn(conn);
        close(sock);
        return;
    }

    type = *conn->data.buf;
    conn->type = type;

    switch (type) {
    case TYPE_THRESHOLD_v1:
        /*
         * thresholding analysis with uri/host  
         */
        event_set(&conn->event, sock, EV_READ,
                  (void *) client_read_v1_header, conn);
        event_add(&conn->event, 0);
        break;
    case TYPE_THRESHOLD_v2:
	/* thresholding for IP analysis only */
	event_set(&conn->event, sock, EV_READ,
		(void *) client_read_v2_header, conn);
	event_add(&conn->event, 0);
	break;
    case TYPE_REMOVE:
    case TYPE_INJECT:
        event_set(&conn->event, sock, EV_READ,
                  (void *) client_read_injection, conn);
        event_add(&conn->event, 0);
        break;
    default:
        free_client_conn(conn);
        close(sock);
        return;
    }

    reset_iov(&conn->data);
}

void
server_driver(int sock, short which, void *args)
{
    int             csock;
    struct sockaddr_in addr;
    socklen_t       addrlen;

    addrlen = sizeof(struct sockaddr);
    csock = accept(sock, (struct sockaddr *) &addr, &addrlen);

    if (csock <= 0) {
        close(csock);
        return;
    }

    if (set_nb(csock)) {
        close(csock);
        return;
    }

    client_conn_t  *new_conn = calloc(sizeof(client_conn_t), 1);

    if (!new_conn) {
        LOG("Out of memory: %s", strerror(errno));
        exit(1);
    }

    new_conn->sock = csock;
    new_conn->conn_addr = (uint32_t) addr.sin_addr.s_addr;
    new_conn->conn_port = (uint16_t) addr.sin_port;

    current_connections =
        g_slist_prepend(current_connections, (gpointer) new_conn);

    event_set(&new_conn->event, csock, EV_READ,
              (void *) client_read_type, new_conn);
    event_add(&new_conn->event, 0);

    return;
}

int
server_init(void)
{
    struct sockaddr_in addr;
    int             sock,
                    v = 1;

    if ((sock = socket(PF_INET, SOCK_STREAM, 0)) <= 0)
        return -1;

    if ((setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
                    (char *) &v, sizeof(v))) < 0)
        return -1;

    if (set_nb(sock))
        return -1;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(bind_port);
    addr.sin_addr.s_addr = inet_addr(bind_addr);

    if (bind(sock, (struct sockaddr *) &addr, sizeof(addr)) < 0)
        return -1;

    if (listen(sock, 1024) < 0)
        return -1;

    event_set(&server_event, sock, EV_READ | EV_PERSIST,
              server_driver, NULL);
    event_add(&server_event, 0);

    return 0;
}

int
parse_args(int argc, char **argv)
{
    extern char    *optarg;
    extern int      optind,
                    opterr,
                    optopt;
    int             c,
                    option_index = 0;
    uint32_t        pass;

    enum {
        conf_help,
        conf_no_uri_check,
        conf_no_site_check,
        conf_bind_addr,
        conf_bind_port,
        /*
         * this is the soft timeout for a blocked srcip. if this src
         * address is not seen for this amount of time making new
         * requests, this will expire that block 
         */
        conf_soft_block_timeout,
        /*
         * This option is set in the format of x:y, where X is the number
         * of connections and Y is the timeframe in which it was seen in
         * seconds. Example: 5:60 would mean to block that source address
         * if it made 5 connections within 60 seconds 
         */
        conf_site_block_ratio,
        conf_uri_block_ratio,
        conf_name,
        conf_no_syslog,
        conf_rbl_zone,
        conf_rbl_negcache_timeout,
        conf_rbl_ns,
	conf_rbl_limit,
	conf_rbl_max_queries,
        conf_server_port,
	conf_no_addr_check,
	conf_addr_block_ratio
    };

    static struct option long_options[] = {
        {"no-uri-check", no_argument, 0, conf_no_uri_check},
        {"no-site-check", no_argument, 0, conf_no_site_check},
	{"no-addr-check", no_argument, 0, conf_no_addr_check},
        {"bind-addr", required_argument, 0, conf_bind_addr},
        {"bind-port", required_argument, 0, conf_bind_port},
        {"server-port", required_argument, 0, conf_server_port},
        {"soft-block-timeout", required_argument, 0,
         conf_soft_block_timeout},
        {"site-block-ratio", required_argument, 0, conf_site_block_ratio},
        {"uri-block-ratio", required_argument, 0, conf_uri_block_ratio},
	{"addr-block-ratio", required_argument, 0, conf_addr_block_ratio},
        {"name", required_argument, 0, conf_name},
        {"no-syslog", no_argument, 0, conf_no_syslog},
        {"rbl-zone", required_argument, 0, conf_rbl_zone},
        {"rbl-ns", required_argument, 0, conf_rbl_ns},
	{"rbl-limit", required_argument, 0, conf_rbl_limit},
	{"rbl-max-queries", required_argument, 0, conf_rbl_max_queries},
        {"rbl-negcache-timeout", required_argument, 0,
         conf_rbl_negcache_timeout},
        {0, 0, 0, 0}
    };

    pass = 1514952012;

    static char    *help =
        "Copyright AOL LLC 2008-2009\n\n"
        "The main goal of this project is to allow a farm of autonomous servers to \n"
        "collect and block malicious addresses maliciously attacking services.\n\n"
        "Initially derived to solve the issues with thresholding HTTP connections via \n"
        "Apache (unable to collect stats between forks in mpm_worker, unable to sync \n"
        "stats on a load balanced farm) this has turned into a service that many \n"
        "applications can use.\n\n"
        "options:\n"
        "  -h, --help            show this help message and exit\n\n"
        "  -U, --no-uri-check    If the administrator wishes to not threshold \n"
        "                        connections via the http URI being fetched by a \n"
        "                        client; you may use this flag to disable it.\n\n"
        "  -S, --no-site-check   if the administrator wishes to not threshold \n"
        "                        connections via the http Host header being fetched by \n"
        "                        a client; you may use this flag to disable it. \n\n"
	"  -A, --no-addr-check   No v2 source-address-only checks. \n\n"
        "  -x, --site-block-ratio=SITE_BLOCK_RATIO \n"
        "                        This flag sets the threshold ratio.  The argument must \n"
        "                        be in the format of X:Y where X equals the number of \n"
        "                        incoming queries and Y representing the window of time \n"
        "                        (in seconds).\n\n"
        "                        For example: 20:60 means \"hold-down the \n"
        "                        source address if 20 requests were made within 60 \n"
        "                        seconds\". It should be noted that this ratio is based \n"
        "                        on the http Host header. \n\n"
        "  -y, --uri-block-ratio=URI_BLOCK_RATIO \n"
        "                        Functionally the same as --site-block-ratio but uses \n"
        "                        the URI of the http request for analysis.\n\n"
	"  -z, --addr-block-ratio=ADDR_BLOCK_RATIO \n"
	"                        This enables the ability for a client to send a much \n"
        "                        smaller payload containing only the source address. \n"
        "                        This used in conjunction with webfw2 + uri/host filter \n"
        "                        with a thrasher action would be an optimal selection \n\n"
        "                        Functionally this works the same as other ratios, but only\n"
        "                        cares about the source-address\n\n" 
        "                        NOTE: client must support V2 thrasher connections.\n\n"
        "  -t, --soft-block-timeout=SOFT_BLOCK_TIMEOUT \n"
        "                        A timeout (in seconds) to expire a held-down address \n"
        "                        if no new connections from this address are reported \n"
        "                        to the daemon. Once another connection is reported the \n"
        "                        timer resets \n\n"
        "  -r, --rbl-zone=RBL_ZONE If the administrator wishes to utilize an RBL service \n"
        "                        as another method of holding-down known baddies and \n"
        "                        bypass ratios, this flag will enable that feature.\n\n"
        "                        The argument must be the zone in which you have your RBL \n"
        "                        set to, e.g., '--rbl-zone dnsbl.yourserver.com'. This \n"
        "                        will prepend addresses to this zone \n"
        "                        '1.0.0.127.dnsbl.yourserver.com.' for lookup.\n\n"
        "  -N, --rbl-negcache-timeout=RBL_NEGCACHE_TIMEOUT\n"
        "                        The time in seconds to keep negative answers \n"
        "                        (NXDOMAIN) in state so the RBL server is not hammered \n\n"
	"  -R, --rbl-ns=RBL_NAMESERVER \n"
	"                        The nameserver to use for RBL checks if not in /etc/resolv.conf\n\n"
#if 0
	"  --rbl-limit=LIMIT \n"
	"                        The number of requests for a single source address before\n" 
	"                        sending an RBL lookup (must be lower than your ratios)\n\n"
#endif
	"  -l, --rbl-max-queries=MAX \n"
	"                        The maximum number of outstanding RBL queries\n\n"
        "  -b, --bind-addr=BIND_ADDR \n"
        "                        Bind services to only this address, default is 0.0.0.0 \n\n"
        "  -p, --bind-port=BIND_PORT \n"
        "                        The port to listen on for the thrasher thresholding \n"
        "                        handler \n\n"
        "  -P, --server-port=SERVER_PORT \n"
        "                        The port to listen on for the thrasher statistics \n"
        "                        interface \n\n"
        "  -L, --no-syslog       The default behaviour of various logs thrasher \n"
        "                        generates is to syslog, this turns this functionality \n"
        "                        off and writes to stdout. \n\n"
        "  -n, --name=NAME       Applies a name to the service, this is good for \n"
        "                        keeping track of different groups/organizations \n"
        "                        running on seprate instances. This can be seen via the \n"
        "                        statistics interface \n\n"
        "  -D                    Daemonize (rawr). \n";


    while ((c = getopt_long(argc, argv, "vDl:USAb:p:P:t:x:y:z:n:Lr:R:l:N:",
                            long_options, &option_index)) > 0) {
        gchar         **splitter;
        switch (c) {
	case 'U':
        case conf_no_uri_check:
            uri_check = 0;
            break;
	case 'S':
        case conf_no_site_check:
            site_check = 0;
            break;
	case 'A':
	case conf_no_addr_check:
	    addr_check = 0;
	    break;
	case 'P':
        case conf_server_port:
            server_port = atoi(optarg);
            break;
	case 't':
        case conf_soft_block_timeout:
            soft_block_timeout = atoll(optarg);
            break;
	case 'y':
        case conf_uri_block_ratio:
            splitter = g_strsplit(optarg, ":", 2);
            uri_ratio.num_connections = atoll(splitter[0]);
            uri_ratio.timelimit = atoll(splitter[1]);
            g_strfreev(splitter);
            break;
	case 'x':
        case conf_site_block_ratio:
            splitter = g_strsplit(optarg, ":", 2);
            site_ratio.num_connections = atoll(splitter[0]);
            site_ratio.timelimit = atoll(splitter[1]);
            g_strfreev(splitter);
            break;
	case 'z':
	case conf_addr_block_ratio:
	    splitter = g_strsplit(optarg, ":", 2);
	    addr_ratio.num_connections = atoll(splitter[0]);
	    addr_ratio.timelimit = atoll(splitter[1]);
	    g_strfreev(splitter);
	    break;
	case 'b':
        case conf_bind_addr:
            bind_addr = optarg;
            break;
	case 'p':
        case conf_bind_port:
            bind_port = atoi(optarg);
            break;
        case 'D':
            rundaemon = 1;
            break;
	case 'n':
        case conf_name:
            process_name = optarg;
            break;
	case 'L':
        case conf_no_syslog:
            syslog_enabled = 0;
            break;
	case 'r':
        case conf_rbl_zone:
            rbl_zone = strdup(optarg);
            break;
	case 'N':
        case conf_rbl_negcache_timeout:
            rbl_negcache_timeout = atoi(optarg);
            break;
	case 'R':
        case conf_rbl_ns:
            rbl_ns = strdup(optarg);
            break;
	case conf_rbl_limit:
	    rbl_limit = atoi(optarg);
	    break;
	case 'l':
	case conf_rbl_max_queries:
	    rbl_max_queries = atoi(optarg);
	    break;
        default:
            printf("Version: %s (%s)\n", VERSION, VERSION_NAME);
            printf("Usage: %s [opts]\n%s", argv[0], help);
            exit(1);
        }
    }

    return 0;
}

gboolean
fill_http_blocks(void *key, blocked_node_t * val, struct evbuffer * buf)
{
    char           *blockedaddr;
    char           *triggeraddr;

    blockedaddr = 
	strdup(inet_ntoa(*(struct in_addr *) &val->saddr));

    triggeraddr =
        strdup(inet_ntoa(*(struct in_addr *) &val->first_seen_addr));

    if (blockedaddr && triggeraddr)
	evbuffer_add_printf(buf, "%-15s %-15s %-15d\n",
                        blockedaddr, triggeraddr, val->count);

    if (blockedaddr) free(blockedaddr);
    if (triggeraddr) free(triggeraddr);

    return FALSE;
}

void
fill_current_connections(client_conn_t * conn, struct evbuffer *buf)
{
    if (conn == NULL)
        return;

    evbuffer_add_printf(buf, "    %-15s %-5d %-15s\n",
                        inet_ntoa(*(struct in_addr *) &conn->conn_addr),
                        ntohs(conn->conn_port), "ESTABLISHED");
}

void
httpd_put_hips(struct evhttp_request *req, void *args)
{
    struct evbuffer *buf;

    buf = evbuffer_new();

    evbuffer_add_printf(buf, "%-15s %-15s %-15s\n",
                        "Blocked IP", "Triggered By", "Count");

    g_tree_foreach(current_blocks, (GTraverseFunc) fill_http_blocks, buf);

    evhttp_send_reply(req, HTTP_OK, "OK", buf);
    evbuffer_free(buf);
}

void
httpd_put_connections(struct evhttp_request *req, void *args)
{
    struct evbuffer *buf;

#if 0
    TAILQ_FOREACH(header, req->output_headers, req->next) {
	printf("%s -> %s\n", key, header->value);
    }
#endif
    buf = evbuffer_new();

    evbuffer_add_printf(buf, "\nCurrent active connections\n");
    evbuffer_add_printf(buf,
                        "    %-15s %-5s %-15s\n", "Addr", "Port", "State");

    g_slist_foreach(current_connections,
                    (GFunc) fill_current_connections, buf);

    evhttp_send_reply(req, HTTP_OK, "OK", buf);
    evbuffer_free(buf);
}

void
httpd_put_config(struct evhttp_request *req, void *args)
{
    struct evbuffer *buf;

    buf = evbuffer_new();

    evbuffer_add_printf(buf, "Thrashd version: %s (%s) [%s]\n", VERSION,
                        VERSION_NAME, process_name);
    evbuffer_add_printf(buf, "Running configuration\n\n");
    evbuffer_add_printf(buf, "  URI Check Enabled:  %s\n",
                        uri_check ? "yes" : "no");
    evbuffer_add_printf(buf, "  Host Check Enabled: %s\n",
                        site_check ? "yes" : "no");
    evbuffer_add_printf(buf, "  Addr Check Enabled: %s\n",
	                addr_check ? "yes" : "no");
    evbuffer_add_printf(buf, "  Bind addr:          %s\n", bind_addr);
    evbuffer_add_printf(buf, "  Bind port:          %d\n", bind_port);
    evbuffer_add_printf(buf, "  Soft block timeout: %d\n\n",
                        soft_block_timeout);
    evbuffer_add_printf(buf,
                        "  Host block ratio: %d hits over %d seconds\n",
                        site_ratio.num_connections, site_ratio.timelimit);
    evbuffer_add_printf(buf,
                        "  URI block ratio:  %d hits over %d seconds\n",
                        uri_ratio.num_connections, uri_ratio.timelimit);
    evbuffer_add_printf(buf,
	                "  ADDR block ratio: %d hits over %d seconds\n\n",
			addr_ratio.num_connections, addr_ratio.timelimit);
    evbuffer_add_printf(buf,
                        "%d addresses currently in hold-down (%u qps)\n",
                        g_tree_nnodes(current_blocks), qps_last);
    evbuffer_add_printf(buf, "Total connections blocked: %llu\n", 
	    total_blocked_connections);
    evbuffer_add_printf(buf, "DNS Query backlog: %d/%d\n", rbl_queries,
	    rbl_max_queries);

    evhttp_send_reply(req, HTTP_OK, "OK", buf);
    evbuffer_free(buf);
}


void
httpd_driver(struct evhttp_request *req, void *arg)
{
    struct evbuffer *buf;

    buf = evbuffer_new();

    evbuffer_add_printf(buf, "Thrashd version: %s [%s]\n", VERSION,
                        process_name);
    evhttp_send_reply(req, HTTP_OK, "OK", buf);
    evbuffer_free(buf);
}

int
webserver_init(void)
{
    struct evhttp  *httpd;
    httpd = evhttp_start("0.0.0.0", server_port);

    if (httpd == NULL)
        return -1;

    evhttp_set_cb(httpd, "/holddowns", httpd_put_hips, NULL);
    evhttp_set_cb(httpd, "/config", httpd_put_config, NULL);
    evhttp_set_cb(httpd, "/connections", httpd_put_connections, NULL);
    evhttp_set_gencb(httpd, httpd_driver, NULL);
    return 0;
}

void
qps_init(void)
{
    struct timeval  tv;

    tv.tv_sec = 1;
    tv.tv_usec = 0;

    evtimer_set(&qps_event, (void *) qps_reset, NULL);
    evtimer_add(&qps_event, &tv);
}

void
qps_reset(int sock, int which, void *args)
{
    qps_last = qps;
    qps = 0;

    qps_init();
}

static struct dsn_c_pvt_sfnt {
    int             val;
    const char     *strval;
} facilities[] = {
    {
    LOG_KERN, "kern"}, {
    LOG_USER, "user"}, {
    LOG_MAIL, "mail"}, {
    LOG_DAEMON, "daemon"}, {
    LOG_AUTH, "auth"}, {
    LOG_SYSLOG, "syslog"}, {
    LOG_LPR, "lpr"}, {
    LOG_NEWS, "news"}, {
    LOG_UUCP, "uucp"}, {
    LOG_CRON, "cron"}, {
    LOG_AUTHPRIV, "authpriv"}, {
    LOG_FTP, "ftp"}, {
    LOG_LOCAL0, "local0"}, {
    LOG_LOCAL1, "local1"}, {
    LOG_LOCAL2, "local2"}, {
    LOG_LOCAL3, "local3"}, {
    LOG_LOCAL4, "local4"}, {
    LOG_LOCAL5, "local5"}, {
    LOG_LOCAL6, "local6"}, {
    LOG_LOCAL7, "local7"}, {
    0, NULL}
};

void
syslog_init(char *facility)
{
    int             i;
    int             facility_num = 0;
    char           *ident;

    if (!syslog_enabled)
        return;

    for (i = 0; facilities[i].strval != NULL; i++) {
        if (strcasecmp(facilities[i].strval, facility) == 0) {
            facility_num = facilities[i].val;
            break;
        }
    }

    if (!facility_num) {
        syslog_enabled = 0;
        fprintf(stderr, "No valid facility, syslog will be turned off\n");
        return;
    }

    if (!(ident = malloc(255))) {
        LOG("Out of memory: %s", strerror(errno));
        exit(1);
    }

    snprintf(ident, 254, "thrashd-%s", process_name);

    openlog(ident, 0, facility_num);
}

void
rbl_init(void)
{
    if (!rbl_zone)
        return;

    if (rbl_ns)
        evdns_nameserver_ip_add(rbl_ns);
    else
        evdns_resolv_conf_parse(DNS_OPTION_NAMESERVERS,
                                "/etc/resolv.conf");

    evdns_set_option("timeout:", "1", DNS_OPTIONS_ALL);
    evdns_set_option("max-timeouts:", "3", DNS_OPTIONS_ALL);

    if (evdns_count_nameservers() <= 0) {
        LOG("Couldn't setup RBL server!");
        exit(1);
    }

    LOG("RBL Zone '%s' initialized", rbl_zone);
}

void
daemonize(const char *path)
{
    int             status;
    int             fd;

    status = fork();
    if (status < 0) {
        fprintf(stderr, "Can't fork!\n");
        exit(1);
    }

    else if (status > 0)
        _exit(0);

#if HAVE_SETSID
    assert(setsid() >= 0);
#elif defined(TIOCNOTTY)
    fd = open("/dev/tty", O_RDWR);

    if (fd >= 0)
        assert(ioctl(fd, TIOCNOTTY, NULL) >= 0);
#endif

    assert(chdir(path) >= 0);

    fd = open("/dev/null", O_RDWR, 0);

    if (fd != -1) {
        dup2(fd, STDIN_FILENO);
        dup2(fd, STDOUT_FILENO);
        dup2(fd, STDERR_FILENO);
        if (fd > 2)
            close(fd);
    }
}

int
main(int argc, char **argv)
{
    globals_init();
    parse_args(argc, argv);
    event_init();
    rbl_init();
    qps_init();

    if (webserver_init() == -1) {
        LOG("ERROR: Could not bind webserver port: %s", strerror(errno));
        return 0;
    }

    if (server_init() == -1) {
        LOG("ERROR: Could not bind to port: %s", strerror(errno));
        return 0;
    }
    syslog_init("local6");

    LOG("Daemon starting...");
    LOG("URI Block Ratio: %d:%d Enabled? %s",
        uri_ratio.num_connections, uri_ratio.timelimit,
	uri_check?"yes":"no");
    LOG("HOST Block Ratio: %d:%d Enabled? %s",
        site_ratio.num_connections, site_ratio.timelimit,
	site_check?"yes":"no");
    LOG("v2 ADDR Block Ratio: %d:%d Enabled? %s",
	    addr_ratio.num_connections, addr_ratio.timelimit,
	    addr_check?"yes":"no");


    if (rundaemon)
        daemonize("/tmp");

    event_loop(0);

    return 0;
}
