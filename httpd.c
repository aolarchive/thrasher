#include "thrasher.h"
#include "version.h"

extern char    *process_name;
extern uint32_t uri_check;
extern uint32_t site_check;
extern uint32_t addr_check;
extern char    *bind_addr;
extern uint16_t bind_port;
extern uint32_t soft_block_timeout;
extern block_ratio_t site_ratio;
extern block_ratio_t uri_ratio;
extern block_ratio_t addr_ratio;
extern int      server_port;
extern uint32_t qps;
extern uint32_t qps_last;
extern uint64_t total_blocked_connections;
extern uint64_t total_queries;
extern int      rbl_queries;
extern int      rbl_max_queries;
extern char    *rbl_zone;
extern int      rbl_negcache_timeout;
extern char    *rbl_ns;
extern uint32_t connection_timeout;

extern block_ratio_t minimum_random_ratio;
extern block_ratio_t maximum_random_ratio;
extern uint32_t recently_blocked_timeout;


extern GTree   *current_blocks;
extern GSList  *current_connections;
extern GTree   *recently_blocked;

extern GHashTable     *uri_table;
extern GHashTable     *host_table;
extern GHashTable     *addr_table;

/* Must be an easier way to figure out when an event is going to fire */
int event_remaining_seconds(struct event *ev) 
{
    void          *event_base;
    struct timeval base_tv;

    event_base = event_get_base(ev);
    event_base_gettimeofday_cached(event_base, &base_tv);
    return ev->ev_timeout.tv_sec - base_tv.tv_sec;
}

gboolean
fill_http_blocks(void *key, blocked_node_t * val, struct evbuffer *buf)
{
    char           blockedaddr[20];
    char           triggeraddr[20];

    strcpy(blockedaddr, inet_ntoa(*(struct in_addr *) &val->saddr));

    strcpy(triggeraddr, inet_ntoa(*(struct in_addr *) &val->first_seen_addr));


    evbuffer_add_printf(buf, "%-15s %-15s %-10d ",
                        blockedaddr, triggeraddr, val->count);

    if (val->timeout.ev_timeout.tv_sec == 0) {
        evbuffer_add_printf(buf, "%-10s ", "N/A");
    } else  {
        evbuffer_add_printf(buf, "%-10d ", event_remaining_seconds(&val->timeout));
    }

    if (val->recent_block_timeout.ev_timeout.tv_sec == 0) {
        evbuffer_add_printf(buf, "%-10s\n", "N/A");
    } else  {
        evbuffer_add_printf(buf, "%-10d ", event_remaining_seconds(&val->recent_block_timeout));
    }
     
    return FALSE;
}

void
fill_current_connections(client_conn_t * conn, struct evbuffer *buf)
{
    if (conn == NULL)
        return;

    evbuffer_add_printf(buf, "%-15s  %-5d  %-10lld  %15.15s  ",
                        inet_ntoa(*(struct in_addr *) &conn->conn_addr),
                        ntohs(conn->conn_port),
                        conn->requests,
                        ctime(&conn->conn_time)+4);

    if (conn->last_time) {
        evbuffer_add_printf(buf, "%15.15s\n",
                            ctime(&conn->last_time)+4);
    } else {
        evbuffer_add_printf(buf, "%-15.15s\n", "N/A");
    }
}

gboolean
fill_http_addr(void *key, qstats_t * val, struct evbuffer *buf)
{
    evbuffer_add_printf(buf, "%-15s  %-15d  ",
                        inet_ntoa(*(struct in_addr *) &val->saddr),
                        val->connections);

    if (val->timeout.ev_timeout.tv_sec == 0) {
        evbuffer_add_printf(buf, "%-10s\n", "N/A");
    } else  {
        evbuffer_add_printf(buf, "%-10d\n", event_remaining_seconds(&val->timeout));
    }

    return FALSE;
}

gboolean
fill_http_urihost(void *key, qstats_t * val, struct evbuffer *buf)
{
    char *colon;

    evbuffer_add_printf(buf, "%-15s  %-15d  ",
                        inet_ntoa(*(struct in_addr *) &val->saddr), 
                        val->connections);

    if (val->timeout.ev_timeout.tv_sec == 0) {
        evbuffer_add_printf(buf, "%-10s  ", "N/A");
    } else  {
        evbuffer_add_printf(buf, "%-10d  ", event_remaining_seconds(&val->timeout));
    }

    /* Print up to 40 chars of the uri or host */
    colon = strchr(key, ':');
    if (colon)
        evbuffer_add_printf(buf, "%.*s ", MIN(40, strlen(colon+1)), colon+1);
        
    evbuffer_add_printf(buf, "\n");
    return FALSE;
}


void
httpd_put_holddowns(struct evhttp_request *req, void *args)
{
    struct evbuffer *buf;

    buf = evbuffer_new();

    evbuffer_add_printf(buf, "%-15s %-15s %-10s %-10s %-10s\n",
                        "Blocked IP", "Triggered By", "Count", "TimeOut", "RecentTO");

    g_tree_foreach(current_blocks, (GTraverseFunc) fill_http_blocks, buf);

    evhttp_add_header(req->output_headers, "Content-Type", "text/plain");
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
                        "%-15s  %-5s  %-10s  %-15s  %-15s\n", 
                        "Addr", "Port", "Requests", "Connection Date", "Last Date");

    g_slist_foreach(current_connections,
                    (GFunc) fill_current_connections, buf);

    evhttp_add_header(req->output_headers, "Content-Type", "text/plain");
    evhttp_send_reply(req, HTTP_OK, "OK", buf);
    evbuffer_free(buf);
}

void
httpd_put_addrs(struct evhttp_request *req, void *args)
{
    struct evbuffer *buf;

    buf = evbuffer_new();

    evbuffer_add_printf(buf, "\nCurrent items in address table\n");
    evbuffer_add_printf(buf,
                        "%-15s  %-15s  %-10s\n", 
                        "Addr", "Connections", "Timeout");

    g_hash_table_foreach(addr_table, (GHFunc) fill_http_addr, buf);

    evhttp_add_header(req->output_headers, "Content-Type", "text/plain");
    evhttp_send_reply(req, HTTP_OK, "OK", buf);
    evbuffer_free(buf);
}

void
httpd_put_uris(struct evhttp_request *req, void *args)
{
    struct evbuffer *buf;

    buf = evbuffer_new();

    evbuffer_add_printf(buf, "\nCurrent items in uri table\n");
    evbuffer_add_printf(buf,
                        "%-15s  %-15s  %-10s  %-s\n", 
                        "Addr", "Connections", "Timeout", "URI (40 char max)");

    g_hash_table_foreach(uri_table, (GHFunc) fill_http_urihost, buf);

    evhttp_add_header(req->output_headers, "Content-Type", "text/plain");
    evhttp_send_reply(req, HTTP_OK, "OK", buf);
    evbuffer_free(buf);
}

void
httpd_put_hosts(struct evhttp_request *req, void *args)
{
    struct evbuffer *buf;

    buf = evbuffer_new();

    evbuffer_add_printf(buf, "\nCurrent items in host table\n");
    evbuffer_add_printf(buf,
                        "%-15s  %-15s  %-10s  %-s\n", 
                        "Addr", "Connections", "Timeout", "Host (40 char max)");

    g_hash_table_foreach(host_table, (GHFunc) fill_http_urihost, buf);

    evhttp_add_header(req->output_headers, "Content-Type", "text/plain");
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
    evbuffer_add_printf(buf, "  URI Check Enabled:     %s\n",
                        uri_check ? "yes" : "no");
    evbuffer_add_printf(buf, "  Host Check Enabled:    %s\n",
                        site_check ? "yes" : "no");
    evbuffer_add_printf(buf, "  Addr Check Enabled:    %s\n",
                        addr_check ? "yes" : "no");
    evbuffer_add_printf(buf, "  Sliding Ratio Enabled: %s\n",
	                recently_blocked ? "yes" : "no");
    evbuffer_add_printf(buf, "  RBL Enabled:           %s\n",
	                rbl_zone ? "yes":"no");

    evbuffer_add_printf(buf, "  Bind addr:             %s\n", bind_addr);
    evbuffer_add_printf(buf, "  Bind port:             %d\n", bind_port);
    evbuffer_add_printf(buf, "  Client Idle Timeout:   %u\n", connection_timeout);
    evbuffer_add_printf(buf, "  Soft block timeout:    %d\n\n", soft_block_timeout);

    evbuffer_add_printf(buf, "  RBL Zone:              %s\n", rbl_zone?rbl_zone:"NULL");
    evbuffer_add_printf(buf, "  RBL Nameserver:        %s\n", rbl_ns?rbl_ns:"NULL");
    evbuffer_add_printf(buf, "  RBL Max Async Queries: %d\n", rbl_max_queries);
    evbuffer_add_printf(buf, "  RBL NegCache Timeout:  %d\n\n", rbl_negcache_timeout);

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
	                "  Sliding Ratio MINIMUM: %d hits over %d seconds\n",
			minimum_random_ratio.num_connections,
			minimum_random_ratio.timelimit);
    evbuffer_add_printf(buf,
	                "  Sliding Ratio MAXIMUM: %d hits over %d seconds\n",
			maximum_random_ratio.num_connections,
			maximum_random_ratio.timelimit);

    evbuffer_add_printf(buf,
	                "  Sliding Ratio Recently Blocked Timeout: %u\n\n",
			recently_blocked_timeout);

    evbuffer_add_printf(buf,
	                "%d clients currently connected\n",
			g_slist_length(current_connections)-1);

    evbuffer_add_printf(buf,
                        "%d addresses currently in hold-down (%u qps)\n",
                        g_tree_nnodes(current_blocks), qps_last);
    evbuffer_add_printf(buf, "Total connections blocked: %llu\n",
                        total_blocked_connections);
    evbuffer_add_printf(buf, "Total queries recv: %llu\n", total_queries);
    evbuffer_add_printf(buf, "DNS Query backlog: %d/%d\n", rbl_queries,
                        rbl_max_queries);

    evhttp_add_header(req->output_headers, "Content-Type", "text/plain");
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

    evhttp_add_header(req->output_headers, "Content-Type", "text/plain");
    evhttp_send_reply(req, HTTP_OK, "OK", buf);
    evbuffer_free(buf);
}

int
webserver_init(void)
{
    struct evhttp  *httpd;
    httpd = evhttp_start(bind_addr, server_port);

    if (httpd == NULL)
        return -1;

    evhttp_set_cb(httpd, "/holddowns", httpd_put_holddowns, NULL);
    evhttp_set_cb(httpd, "/config", httpd_put_config, NULL);
    evhttp_set_cb(httpd, "/connections", httpd_put_connections, NULL);
    evhttp_set_cb(httpd, "/addrs", httpd_put_addrs, NULL);
    evhttp_set_cb(httpd, "/uris", httpd_put_uris, NULL);
    evhttp_set_cb(httpd, "/hosts", httpd_put_hosts, NULL);
    evhttp_set_gencb(httpd, httpd_driver, NULL);
    return 0;
}
