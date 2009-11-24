#include "thrasher.h"
#include "version.h"

#define MAX_URI_SIZE  1500
#define MAX_HOST_SIZE 1500

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
static int      rbl_max_queries;
static int      rbl_queries;
static uint32_t rbl_negcache_timeout;
static uint64_t total_blocked_connections;
static uint64_t total_queries;
GSList         *current_connections;
GTree          *current_blocks;
GHashTable     *uri_table;
GHashTable     *host_table;
GHashTable     *addr_table;
GTree          *rbl_negative_cache;
GHashTable     *uri_states;
GHashTable     *host_states;
GKeyFile       *config_file;
GTree          *recently_blocked;
GRand          *randdata;

static uint32_t recently_blocked_timeout;
static block_ratio_t minimum_random_ratio;
static block_ratio_t maximum_random_ratio;

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
    if (!conn)
        return;

    LOG("Lost connection from %s:%d",
        inet_ntoa(*(struct in_addr *) &conn->conn_addr),
        ntohs(conn->conn_port));

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
    uri_check = 1;
    site_check = 1;
    addr_check = 1;
    bind_addr = "0.0.0.0";
    bind_port = 1972;
    server_port = 1979;
    soft_block_timeout = 60;
    site_ratio.num_connections = 10;
    uri_ratio.num_connections = 10;
    site_ratio.timelimit = 60;
    uri_ratio.timelimit = 60;
    addr_ratio.num_connections = 100;
    addr_ratio.timelimit = 10;
    qps = 0;
    qps_last = 0;
    current_connections = g_slist_alloc();
    current_blocks = g_tree_new((GCompareFunc) uint32_cmp);
    uri_table = g_hash_table_new(g_str_hash, g_str_equal);
    host_table = g_hash_table_new(g_str_hash, g_str_equal);
    addr_table = g_hash_table_new(g_str_hash, g_str_equal);
    process_name = "default";
    syslog_enabled = 1;
    rundaemon = 0;
    rbl_zone = NULL;
    rbl_negative_cache = g_tree_new((GCompareFunc) uint32_cmp);
    rbl_negcache_timeout = 10;
    rbl_max_queries = 0;
    rbl_queries = 0;
    total_blocked_connections = 0;
    total_queries = 0;
    config_file = NULL;
    randdata = NULL;
    recently_blocked = NULL;
    recently_blocked_timeout = 120;
}

int
set_nb(int sock)
{
    return fcntl(sock, F_SETFL, fcntl(sock, F_GETFL, 0) | O_NONBLOCK);
}

void
slide_ratios(blocked_node_t *bnode)
{
    uint32_t last_conn, last_time;

    if(!bnode)
        return;

    last_conn = bnode->ratio.num_connections;
    last_time = bnode->ratio.timelimit;

    if (!last_conn && !last_time)
    {
        last_conn = g_rand_int_range(randdata, 
                minimum_random_ratio.num_connections,
                maximum_random_ratio.num_connections);
	last_time = g_rand_int_range(randdata,
		minimum_random_ratio.timelimit,
		maximum_random_ratio.timelimit);
    }
    else {
        if (minimum_random_ratio.num_connections == last_conn)
            last_conn--;

        if (maximum_random_ratio.timelimit == last_time)
            last_time++;

        last_conn = g_rand_int_range(randdata,
                minimum_random_ratio.num_connections,
                last_conn);

        last_time = g_rand_int_range(randdata,
		last_time, maximum_random_ratio.timelimit);
    }

    if (last_conn <= minimum_random_ratio.num_connections ||
            last_time >= maximum_random_ratio.timelimit)
    {
        last_conn = g_rand_int_range(randdata,
                minimum_random_ratio.num_connections,
                maximum_random_ratio.num_connections);

	last_time = g_rand_int_range(randdata,
		minimum_random_ratio.timelimit,
		maximum_random_ratio.timelimit);
    }
    
#ifdef DEBUG
    LOG("our new random ratio is %d:%d",
	    last_conn, last_time);
#endif
    bnode->ratio.num_connections = last_conn;
    bnode->ratio.timelimit = last_time;
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
    struct in_addr *in_addrs;
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

    if (in_addrs) {
        cconn.conn_addr = (uint32_t) in_addrs[0].s_addr;
        block_addr(&cconn, qsnode.saddr);
    } else
        block_addr(NULL, qsnode.saddr);

    LOG("holding down address %s triggered by RBL",
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
        LOG("addr %u already in negative cache, not querying rbl", addr);
#endif
        return;
    }

    if ((rbl_max_queries) && rbl_queries >= rbl_max_queries) {
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
    evdns_resolve_ipv4(query, 0,
                       (void *) get_rbl_answer, (void *) addrarg);

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

    /* which will tell us whether this is a timer or not,
       since manual removes will set which to 0, we skip
       recently_blocked insert */
    if (recently_blocked && which)
    {
	/* if we have our moving ratios enabled we 
	   put the blocked node into recently_blocked
	*/
	struct timeval tv;

	evtimer_del(&bnode->recent_block_timeout);

	/* slide our windows around */
	slide_ratios(bnode);

	/* reset our count */
	bnode->count = 0;

	/* load this guy up into our recently blocked list */
	g_tree_insert(recently_blocked, 
		&bnode->saddr, bnode);

	/* set our timeout to the global */
	tv.tv_sec = recently_blocked_timeout;
	tv.tv_usec = 0;

	evtimer_set(&bnode->recent_block_timeout,
		(void *)expire_recent_bnode, bnode);
	evtimer_add(&bnode->recent_block_timeout, &tv);

#if DEBUG
	LOG("Placing %s into recently blocked list with a ratio of %d:%d",
		inet_ntoa(*(struct in_addr *) &bnode->saddr),
		    bnode->ratio.num_connections, bnode->ratio.timelimit);
#endif
	return;
    }

    free(bnode);
}

void
expire_recent_bnode(int sock, short which, blocked_node_t *bnode)
{

#ifdef DEBUG
    LOG("expire_recent_bnode(%p) %s",
	    bnode, inet_ntoa(*(struct in_addr *) &bnode->saddr));
#endif

    evtimer_del(&bnode->recent_block_timeout);
    g_tree_remove(recently_blocked, &bnode->saddr);
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
block_addr(client_conn_t *conn, uint32_t addr)
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

    bnode->saddr = addr;
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

        bnode = block_addr(conn, stats->saddr);

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
    struct timeval  tv;
    blocked_node_t *bnode;

    qps++;
    total_queries++;

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

    if (recently_blocked && (bnode = 
		g_tree_lookup(recently_blocked, &conn->query.saddr)))
    {
	/* this address has been recently expired from the current_blocks
	   and placed into the recently_blocked list. */
	if(bnode->count++ == 0)
	{
	    /* This is the first packet we have seen from this address 
	       since it was put into the recently_blocked tree. */
	    evtimer_del(&bnode->recent_block_timeout);


	    /* since we only end up in the recently_blocked list after 
	       a node has been blocked, then expired via expire_bnode(), 
	       expire_bnode() shifts around the ratios (bnode->ratio)
	       randomly. We use this data to set our packets/window */
	    tv.tv_sec  = bnode->ratio.timelimit;
	    tv.tv_usec = 0;

	    /* if this timer is every reached, it means that we never
	       hit our ratio, thus we need to expire it from the
	       recently_blocked list */ 

	    evtimer_set(&bnode->recent_block_timeout,
		    (void *)expire_recent_bnode, bnode);
	    evtimer_add(&bnode->recent_block_timeout, &tv);
	}

	if (bnode->count >= bnode->ratio.num_connections)
	{
	    /* this connection deserves to be blocked */
	    
	    /* remove from our recently blocked list */
	    evtimer_del(&bnode->recent_block_timeout);
	    g_tree_remove(recently_blocked, &conn->query.saddr);

	    /* insert into our block tree */
	    g_tree_insert(current_blocks, &bnode->saddr, bnode);

	    /* set our timeout to the normal timelimit */
	    tv.tv_sec  = soft_block_timeout;
	    tv.tv_usec = 0;

	    evtimer_set(&bnode->timeout, (void *)expire_bnode, bnode);
	    evtimer_add(&bnode->timeout, &tv);

	    return 1;
	}

	return 0;
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

    switch (conn->type) {
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

        if (uri_check && update_thresholds(conn, ukey, stat_type_uri))
            blocked = 1;

        if (site_check && update_thresholds(conn, hkey, stat_type_host))
            blocked = 1;

        break;
    case TYPE_THRESHOLD_v2:
        /*
         * with v2 we only care about the source-address 
         */

        if (addr_check <= 0)
            break;

        hkeylen = 13;

        if (!(hkey = calloc(hkeylen, 1))) {
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
    int             blocked;

    if (!conn->data.buf)
        /*
         * if the connection has an ID, then set it to 5 bytes of reading, 
         * else make it only 1 byte 
         */
        initialize_iov(&conn->data,
                       conn->id ?
                       sizeof(uint32_t) +
                       sizeof(uint8_t) : sizeof(uint8_t));

    if (do_thresholding(conn))
        blocked = 1;
    else
        blocked = 0;

    if (conn->id) {
        memcpy(conn->data.buf, &conn->id, sizeof(uint32_t));
        conn->data.buf[4] = blocked;
    } else
        *conn->data.buf = blocked;

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

#if DEBUG
    LOG("%d %d", conn->query.uri_len, conn->query.host_len);
#endif

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
client_read_v3_header(int sock, short which, client_conn_t * conn)
{
    /*
     * version 3 header includes an extra 32 bit field at the start of
     * the packet. This allows a client to set an ID which will be echoed
     * along with the response. Otherwise it's just like v1 
     */
    int             ioret;
    uint32_t        id;

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
                  (void *) client_read_v3_header, conn);
        event_add(&conn->event, 0);
        return;
    }

    memcpy(&conn->id, conn->data.buf, sizeof(uint32_t));
    reset_iov(&conn->data);

#ifdef DEBUG
    LOG("Got ident %u", ntohs(conn->id));
#endif

    /*
     * go back to reading a v1 like packet 
     */
    event_set(&conn->event, sock, EV_READ,
              (void *) client_read_v1_header, conn);
    event_add(&conn->event, 0);
}

void
client_read_v2_header(int sock, short which, client_conn_t * conn)
{
    int             ioret;
    uint32_t        saddr;

    if (!conn->data.buf)
        initialize_iov(&conn->data, 4);

    ioret = read_iov(&conn->data, sock);

    if (ioret < 0) {
        free_client_conn(conn);
        close(sock);
        return;
    }

    if (ioret > 0) {
        event_set(&conn->event, sock, EV_READ,
                  (void *) client_read_v2_header, conn);
        event_add(&conn->event, 0);
        return;
    }

    memcpy(&saddr, conn->data.buf, sizeof(uint32_t));
    conn->query.saddr = saddr;
    reset_iov(&conn->data);

    /*
     * v2 allows us to just recv a source address, thus we can go directly 
     * into processing the data 
     */
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

#ifdef DEBUG
    LOG("ulen %d hlen %d", urilen, hostlen);
#endif

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
        if ((bnode = g_tree_lookup(current_blocks, &saddr))) {
            bnode->count++;
            total_blocked_connections++;
            break;
        }

	/* this is starting to get a little hacky I think. We can re-factor
	   if I ever end up doing any other types of features */
	if (recently_blocked && 
		(bnode = g_tree_lookup(recently_blocked , &saddr)))
	    /* remove the bnode from the recently blocked list 
	       so the bnode is now set to this instead of a new
	       allocd version */
	{
	    g_tree_remove(recently_blocked, &saddr);
	    /* unset the recently_blocked timeout */
	    evtimer_del(&bnode->recent_block_timeout);
	}
	else
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
        /*
         * thresholding for IP analysis only 
         */
        event_set(&conn->event, sock, EV_READ,
                  (void *) client_read_v2_header, conn);
        event_add(&conn->event, 0);
        break;
    case TYPE_THRESHOLD_v3:
	/* just like v1 but with a 32bit identification header */
        event_set(&conn->event, sock, EV_READ,
                  (void *) client_read_v3_header, conn);
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

    LOG("New connection from %s:%d",
        inet_ntoa(*(struct in_addr *) &new_conn->conn_addr),
        ntohs(new_conn->conn_port));

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

void
load_config(const char *file)
{
    GKeyFileFlags   flags;
    int             i;
    GError         *error = NULL;

    typedef enum {
        _c_f_t_str = 1,
        _c_f_t_int,
	_c_f_t_trie,
        _c_f_t_ratio
    } _c_f_t;

    struct _c_f_in {
        char           *parent;
        char           *key;
        _c_f_t          type;
        void           *var;
    } c_f_in[] = {
        {
        "thrashd", "name", _c_f_t_str, &process_name}, {
        "thrashd", "uri-check", _c_f_t_int, &uri_check}, {
        "thrashd", "host-check", _c_f_t_int, &site_check}, {
        "thrashd", "addr-check", _c_f_t_int, &addr_check}, {
        "thrashd", "http-listen-port", _c_f_t_int, &server_port}, {
        "thrashd", "listen-port", _c_f_t_int, &bind_port}, {
        "thrashd", "listen-addr", _c_f_t_str, &bind_addr}, {
        "thrashd", "block-timeout", _c_f_t_int, &soft_block_timeout}, {
        "thrashd", "uri-ratio", _c_f_t_ratio, &uri_ratio}, {
        "thrashd", "host-ratio", _c_f_t_ratio, &site_ratio}, {
        "thrashd", "addr-ratio", _c_f_t_ratio, &addr_ratio}, {
        "thrashd", "daemonize", _c_f_t_int, &rundaemon}, {
        "thrashd", "syslog", _c_f_t_int, &syslog_enabled}, {
        "thrashd", "rbl-zone", _c_f_t_str, &rbl_zone}, {
        "thrashd",
                "rbl-negative-cache-timeout", _c_f_t_int,
                &rbl_negcache_timeout}, {
        "thrashd", "rbl-nameserver", _c_f_t_str, &rbl_ns}, {
        "thrashd", "rbl-max-query", _c_f_t_int, &rbl_max_queries}, {
	"thrashd", "rand-ratio", _c_f_t_trie, &recently_blocked}, {  
        "thrashd", "min-rand-ratio", _c_f_t_ratio, &minimum_random_ratio}, {
	"thrashd", "max-rand-ratio", _c_f_t_ratio, &maximum_random_ratio}, {    
        "thrashd", "recently-blocked-timeout", _c_f_t_int, 
	        &recently_blocked_timeout}, {
        "thrashd", "rbl-negative-cache-timeout", _c_f_t_int,
	        &rbl_negcache_timeout}, {
        "thrashd", "rbl-zone", _c_f_t_str, &rbl_zone}, {
	"thrashd", "rbl-nameserver", _c_f_t_str, &rbl_ns}, {
	"thrashd", "rbl-max-queries", _c_f_t_int,
                &rbl_max_queries}, {	
        NULL, NULL, 0, NULL}
    };

    config_file = g_key_file_new();

    flags = G_KEY_FILE_KEEP_COMMENTS;

    if (!g_key_file_load_from_file(config_file, file, flags, &error))
    {
	LOG("Error loading config: ");
	exit(1);
    }

    for (i = 0; c_f_in[i].parent != NULL; i++) {
        char          **svar;
        char           *str;
        int            *ivar;
	GTree          **tvar;
        block_ratio_t  *ratio;
        gchar         **splitter;

        if (!g_key_file_has_key(config_file,
                                c_f_in[i].parent, c_f_in[i].key, &error))
            continue;

        switch (c_f_in[i].type) {

        case _c_f_t_str:
            svar = (char **) c_f_in[i].var;
            *svar = g_key_file_get_string(config_file,
                                          c_f_in[i].parent,
                                          c_f_in[i].key, NULL);
            break;
	case _c_f_t_trie:
	    tvar = (GTree **) c_f_in[i].var;
	    *tvar = g_tree_new((GCompareFunc) uint32_cmp);
	    break;
        case _c_f_t_int:
            ivar = (int *) c_f_in[i].var;
            *ivar = g_key_file_get_integer(config_file,
                                           c_f_in[i].parent,
                                           c_f_in[i].key, NULL);
            break;
        case _c_f_t_ratio:
            ratio = (block_ratio_t *) c_f_in[i].var;
            str = g_key_file_get_string(config_file,
                                        c_f_in[i].parent,
                                        c_f_in[i].key, NULL);
            splitter = g_strsplit(str, ":", 2);
            ratio->num_connections = atoll(splitter[0]);
            ratio->timelimit = atoll(splitter[1]);
            g_strfreev(splitter);
            break;
        }
    }

    g_key_file_free(config_file);
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

    static char *help = 
        "Copyright AOL LLC 2008-2009\n\n"
        "The main goal of this project is to allow a farm of autonomous servers to \n"
        "collect and block malicious addresses maliciously attacking services.\n\n"
        "Initially derived to solve the issues with thresholding HTTP connections via \n"
        "Apache (unable to collect stats between forks in mpm_worker, unable to sync \n"
        "stats on a load balanced farm) this has turned into a service that many \n"
        "applications can use.\n\n"
	"Options: \n"
	"   -h:        Help me!!\n"
	"   -v:        Version\n"
	"   -c <file>: Configuration file\n";

    while ((c = getopt (argc, argv, "hvc:")) != -1)
    {
	switch(c)
	{
	    case 'c':
		load_config(optarg);
		break;
	    case 'v':
		printf("%s (%s)\n", VERSION, VERSION_NAME);
		exit(1);
	    case 'h':
		printf("Usage: %s [opts]\n%s", argv[0], help);
		exit(1);
	    default:
		printf("Unknown option %s\n", optarg);
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

    blockedaddr = strdup(inet_ntoa(*(struct in_addr *) &val->saddr));

    triggeraddr =
        strdup(inet_ntoa(*(struct in_addr *) &val->first_seen_addr));

    if (blockedaddr && triggeraddr)
        evbuffer_add_printf(buf, "%-15s %-15s %-15d\n",
                            blockedaddr, triggeraddr, val->count);

    if (blockedaddr)
        free(blockedaddr);
    if (triggeraddr)
        free(triggeraddr);

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
    evbuffer_add_printf(buf, "Total queries recv: %llu\n", total_queries);
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

void
log_startup(void)
{
    LOG("Name:             %s", process_name);

    if (uri_check) {
        LOG("URI Block Ratio:  %u connections within %u seconds",
            uri_ratio.num_connections, uri_ratio.timelimit);
    } else {
        LOG("URI Block:        DISABLED");
    }

    if (site_check) {
        LOG("Host Block Ratio: %u connections within %u seconds",
            site_ratio.num_connections, site_ratio.timelimit);
    } else {
        LOG("Host Block:       DISABLED");
    }

    if (addr_check) {
        LOG("Addr Block Ratio: %u connections within %u seconds",
            addr_ratio.num_connections, addr_ratio.timelimit);
    } else {
        LOG("Host Block:       DISABLED");
    }

    LOG("HTTP Listen Port: %d", server_port);
    LOG("Bind addr:        %s", bind_addr);
    LOG("Listen Port:      %d", bind_port);
    LOG("Block Timeout:    %d", soft_block_timeout);

    if (rbl_zone) {
        LOG("RBL:                  ENABLED");
        LOG("RBL Zone:             %s", rbl_zone);
        LOG("RBL Nameserver:       %s", rbl_ns);
        LOG("RBL Negative Timeout: %d", rbl_negcache_timeout);
        LOG("RBL Max Queries:      %d", rbl_max_queries);
    } else {
        LOG("RBL:              DISABLED");
    }


}

void segvfunc(int sig)
{
    int c, i;
    void *funcs[128];
    char **names;

    c = backtrace(funcs, 128);
    names = backtrace_symbols(funcs, c);

    for (i = 0; i < c; i++)
	LOG("%s", names[i]);

    free(names);

    signal(sig, SIG_DFL);
    kill(getpid(), sig);
}


int
main(int argc, char **argv)
{
    globals_init();
    parse_args(argc, argv);
    event_init();
    rbl_init();
    qps_init();

    signal(SIGSEGV, segvfunc);

    randdata = g_rand_new();

    if (webserver_init() == -1) {
        LOG("ERROR: Could not bind webserver port: %s", strerror(errno));
        return 0;
    }

    if (server_init() == -1) {
        LOG("ERROR: Could not bind to port: %s", strerror(errno));
        return 0;
    }

    syslog_init("local6");
    log_startup();

    if (rundaemon)
        daemonize("/tmp");

    event_loop(0);

    return 0;
}
