#include "thrasher.h"
#include "version.h"
#include <inttypes.h>

extern char    *process_name;
extern uint32_t uri_check;
extern uint32_t site_check;
extern uint32_t addr_check;
extern char    *bind_addr;
extern uint16_t bind_port;
extern uint32_t soft_block_timeout;
extern uint32_t hard_block_timeout;
extern block_ratio_t host_ratio;
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
extern uint32_t velocity_num;

extern block_ratio_t minimum_random_ratio;
extern block_ratio_t maximum_random_ratio;
extern uint32_t recently_blocked_timeout;


extern GTree   *current_blocks;
extern GSList  *current_connections;
extern GTree   *recently_blocked;

extern GHashTable     *uri_table;
extern GHashTable     *host_table;
extern GHashTable     *addr_table;

extern GHashTable     *uris_ratio_table;

/* Must be an easier way to figure out when an event is going to fire */
int event_remaining_seconds(struct event *ev) 
{
    struct timeval now_tv;
    struct timeval event_tv;
    struct timeval remaining_tv;

    event_pending(ev, EV_TIMEOUT, &event_tv);
    evutil_gettimeofday(&now_tv, NULL);
    evutil_timersub(&event_tv, &now_tv, &remaining_tv);

    return remaining_tv.tv_sec;
}

gboolean
fill_http_blocks(void *key, blocked_node_t * val, struct evbuffer *buf)
{
    char           blockedaddr[20] = { 0 };
    char           triggeraddr[20] = { 0 };

    strncpy(blockedaddr, inet_ntoa(*(struct in_addr *) &val->saddr), sizeof(blockedaddr) - 1);
    strncpy(triggeraddr, inet_ntoa(*(struct in_addr *) &val->first_seen_addr), sizeof(triggeraddr) - 1);


    evbuffer_add_printf(buf, "%-15s %-15s %-10d ",
                        blockedaddr, triggeraddr, val->count);

    if (val->count == 0) {
        evbuffer_add_printf(buf, "%-8s ", "N/A");
    } else if (val->avg_distance_usec == 0) {
        evbuffer_add_printf(buf, "%-8s ", "Infinite");
    } else {
        struct timeval now_tv;
        evutil_gettimeofday(&now_tv, NULL);

        uint64_t arrival_gap = (now_tv.tv_sec - val->last_time.tv_sec) * 1000000
                             + (now_tv.tv_usec - val->last_time.tv_usec);

        double avg_distance_usec = (val->avg_distance_usec * (velocity_num - 1) + arrival_gap) / velocity_num;

        evbuffer_add_printf(buf, "%9.3f ", (double)1000000.0/avg_distance_usec);

    }

    if (val->timeout.ev_timeout.tv_sec == 0) {
        evbuffer_add_printf(buf, "%-8s ", "N/A");
    } else  {
        evbuffer_add_printf(buf, "%-8d ", event_remaining_seconds(&val->timeout));
    }

    if (val->hard_timeout.ev_timeout.tv_sec == 0) {
        evbuffer_add_printf(buf, "%-8s ", "N/A");
    } else  {
        evbuffer_add_printf(buf, "%-8d ", event_remaining_seconds(&val->hard_timeout));
    }

    if (val->recent_block_timeout.ev_timeout.tv_sec == 0) {
        evbuffer_add_printf(buf, "%-8s\n", "N/A");
    } else  {
        evbuffer_add_printf(buf, "%-8d\n", event_remaining_seconds(&val->recent_block_timeout));
    }
     
    return FALSE;
}

gboolean
fill_http_blocks_html(void *key, blocked_node_t * val, struct evbuffer *buf)
{
    char           blockedaddr[20] = { 0 };
    char           triggeraddr[20] = { 0 };

    strncpy(blockedaddr, inet_ntoa(*(struct in_addr *) &val->saddr), sizeof(blockedaddr) - 1);
    strncpy(triggeraddr, inet_ntoa(*(struct in_addr *) &val->first_seen_addr), sizeof(triggeraddr) - 1);


    evbuffer_add_printf(buf, "{ip:\"%s\", conn:\"%s\", c:%d, ",
                        blockedaddr, triggeraddr, val->count);

    if (val->timeout.ev_timeout.tv_sec == 0) {
        evbuffer_add_printf(buf, "s:\"N/A\",");
    } else  {
        evbuffer_add_printf(buf, "s:%d,", event_remaining_seconds(&val->timeout));
    }

    if (val->hard_timeout.ev_timeout.tv_sec == 0) {
        evbuffer_add_printf(buf, "h:\"N/A\",");
    } else  {
        evbuffer_add_printf(buf, "h:%d, ", event_remaining_seconds(&val->hard_timeout));
    }

    if (val->recent_block_timeout.ev_timeout.tv_sec == 0) {
        evbuffer_add_printf(buf, "r:\"N/A\"},");
    } else  {
        evbuffer_add_printf(buf, "r:%d},", event_remaining_seconds(&val->recent_block_timeout));
    }
     
    return FALSE;
}

void
fill_current_connections(client_conn_t * conn, struct evbuffer *buf)
{
    if (conn == NULL)
        return;

    evbuffer_add_printf(buf, "%-15s  %-5d  %-10"PRIu64"  %15.15s  ",
                        inet_ntoa(*(struct in_addr *) &conn->conn_addr),
                        ntohs(conn->conn_port),
                        conn->requests,
                        ctime(&conn->conn_time)+4);

    if (conn->last_time.tv_sec) {
        evbuffer_add_printf(buf, "%15.15s\n",
                            ctime(&conn->last_time.tv_sec)+4);
    } else {
        evbuffer_add_printf(buf, "%-15.15s\n", "N/A");
    }
}

void
fill_current_connections_html(client_conn_t * conn, struct evbuffer *buf)
{
    if (conn == NULL)
        return;

    evbuffer_add_printf(buf, "{ip:\"%s\", p:%d, r:%lld, cd:\"%15.15s\", ",
                        inet_ntoa(*(struct in_addr *) &conn->conn_addr),
                        ntohs(conn->conn_port),
                        conn->requests,
                        ctime(&conn->conn_time)+4);

    if (conn->last_time) {
        evbuffer_add_printf(buf, "ld:\"%15.15s\"},",
                            ctime(&conn->last_time)+4);
    } else {
        evbuffer_add_printf(buf, "ld:\"N/A\"},");
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
fill_http_addr_html(void *key, qstats_t * val, struct evbuffer *buf)
{
    evbuffer_add_printf(buf, "{ip:\"%s\", c:%d, ",
                        inet_ntoa(*(struct in_addr *) &val->saddr),
                        val->connections);

    if (val->timeout.ev_timeout.tv_sec == 0) {
        evbuffer_add_printf(buf, "t:\"N/A\"},");
    } else  {
        evbuffer_add_printf(buf, "t:%d},", event_remaining_seconds(&val->timeout));
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
        evbuffer_add_printf(buf, "%.*s ", (int)MIN(40, strlen(colon+1)), colon+1);
        
    evbuffer_add_printf(buf, "\n");
    return FALSE;
}

gboolean
fill_http_urihost_html(void *key, qstats_t * val, struct evbuffer *buf)
{
    char *colon;

    evbuffer_add_printf(buf, "{ip:\"%s\", c:%d, ",
                        inet_ntoa(*(struct in_addr *) &val->saddr), 
                        val->connections);

    if (val->timeout.ev_timeout.tv_sec == 0) {
        evbuffer_add_printf(buf, "t:\"N/A\",");
    } else  {
        evbuffer_add_printf(buf, "t:%d,", event_remaining_seconds(&val->timeout));
    }

    /* Print up to 40 chars of the uri or host */
    /* ALW - Maybe need to escape this */
    colon = strchr(key, ':');
    if (colon)
        evbuffer_add_printf(buf, "u:\"%.*s\"},", MIN(40, strlen(colon+1)), colon+1);
    else
        evbuffer_add_printf(buf, "u:\"\"},");
        
    return FALSE;
}

gboolean
fill_http_uriratio(void *key, block_ratio_t * val, struct evbuffer *buf)
{
    evbuffer_add_printf(buf,
                        "  %30.30s:  %d hits over %d seconds\n",
                        (char*)key,
                        val->num_connections, val->timelimit);

    return FALSE;
}



void
httpd_put_holddowns(struct evhttp_request *req, void *args)
{
    struct evbuffer *buf;

    buf = evbuffer_new();

    evbuffer_add_printf(buf, "%-15s %-15s %-10s %-9s %-8s %-8s %-8s\n",
                        "Blocked IP", "Triggered By", "Count", "Velocity", "Soft", "Hard", "Recent");

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
    evbuffer_add_printf(buf, "  Hard block timeout:    %d\n\n", hard_block_timeout);

    evbuffer_add_printf(buf, "  RBL Zone:              %s\n", rbl_zone?rbl_zone:"NULL");
    evbuffer_add_printf(buf, "  RBL Nameserver:        %s\n", rbl_ns?rbl_ns:"NULL");
    evbuffer_add_printf(buf, "  RBL Max Async Queries: %d\n", rbl_max_queries);
    evbuffer_add_printf(buf, "  RBL NegCache Timeout:  %d\n\n", rbl_negcache_timeout);

    evbuffer_add_printf(buf,
                        "  Host block ratio: %d hits over %d seconds\n",
                        host_ratio.num_connections, host_ratio.timelimit);
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
    evbuffer_add_printf(buf, "Total connections blocked: %"PRIu64"\n",
                        total_blocked_connections);
    evbuffer_add_printf(buf, "Total queries recv: %"PRIu64"\n", total_queries);
    evbuffer_add_printf(buf, "DNS Query backlog: %d/%d\n", rbl_queries,
                        rbl_max_queries);

    if (uris_ratio_table) {
        evbuffer_add_printf(buf, "\nURIs Ratio Table:\n");
        g_hash_table_foreach(uris_ratio_table, (GHFunc) fill_http_uriratio, buf);
    }

    evhttp_add_header(req->output_headers, "Content-Type", "text/plain");
    evhttp_send_reply(req, HTTP_OK, "OK", buf);
    evbuffer_free(buf);
}

void
httpd_put_html_start(struct evbuffer *buf, char *title)
{
    evbuffer_add_printf(buf, "<head><title>Thrashd - %s</title><script src=\"http://yui.yahooapis.com/3.4.1/build/yui/yui-min.js\"></script></head>", title);
    evbuffer_add_printf(buf, "<body>");
    evbuffer_add_printf(buf, "<a href='/connections.html'>Connections</a>&nbsp;");
    evbuffer_add_printf(buf, "<a href='/holddowns.html'>Holddowns</a>&nbsp;");
    evbuffer_add_printf(buf, "<a href='/addrs.html'>Addresses</a>&nbsp;");
    evbuffer_add_printf(buf, "<a href='/hosts.html'>Hosts</a>&nbsp;");
    evbuffer_add_printf(buf, "<a href='/uris.html'>URIs</a>&nbsp;");
    evbuffer_add_printf(buf, "<hr><div id=\"table\"></div>");
    evbuffer_add_printf(buf, "<script type=\"text/javascript\">");
    evbuffer_add_printf(buf, "YUI().use(\"datatable-sort\", function (Y) {");
}

void
httpd_put_html_end(struct evbuffer *buf, char *summary)
{
    evbuffer_add_printf(buf, "], dt1 = new Y.DataTable.Base({columnset:cols, recordset:data, summary:\"%s\"}).plug(Y.Plugin.DataTableSort).render(\"#table\"); });", summary);
    evbuffer_add_printf(buf, "</script></body>");
}

void
httpd_put_holddowns_html (struct evhttp_request *req, void *arg)
{
    struct evbuffer *buf;

    buf = evbuffer_new();
    httpd_put_html_start(buf, "Hold downs");
    evbuffer_add_printf(buf, "var cols = [");
    evbuffer_add_printf(buf, "  {key:\"ip\", label:\"Blocked IP\", sortable:true},");
    evbuffer_add_printf(buf, "  {key:\"conn\", label:\"Triggered By\", sortable:true},");
    evbuffer_add_printf(buf, "  {key:\"c\", label:\"Count\", sortable:true},");
    evbuffer_add_printf(buf, "  {key:\"s\", label:\"Soft (s)\", sortable:true},");
    evbuffer_add_printf(buf, "  {key:\"h\", label:\"Hard (s)\", sortable:true},");
    evbuffer_add_printf(buf, "  {key:\"r\", label:\"Recent (s)\", sortable:true}");
    evbuffer_add_printf(buf, "], data = [");
    g_tree_foreach(current_blocks, (GTraverseFunc) fill_http_blocks_html, buf);
    httpd_put_html_end(buf, "Hold downs");

    evhttp_add_header(req->output_headers, "Content-Type", "text/html");
    evhttp_send_reply(req, HTTP_OK, "OK", buf);
    evbuffer_free(buf);
}



void
httpd_put_connections_html (struct evhttp_request *req, void *arg)
{
    struct evbuffer *buf;

    buf = evbuffer_new();
    httpd_put_html_start(buf, "Connections");
    evbuffer_add_printf(buf, "var cols = [");
    evbuffer_add_printf(buf, "  {key:\"ip\", label:\"Address\", sortable:true},");
    evbuffer_add_printf(buf, "  {key:\"p\", label:\"Port\", sortable:true},");
    evbuffer_add_printf(buf, "  {key:\"r\", label:\"Requests\", sortable:true},");
    evbuffer_add_printf(buf, "  {key:\"cd\", label:\"Connection Date\", sortable:true},");
    evbuffer_add_printf(buf, "  {key:\"ld\", label:\"Last Date\", sortable:true},");
    evbuffer_add_printf(buf, "], data = [");
    g_slist_foreach(current_connections, (GFunc) fill_current_connections_html, buf);
    httpd_put_html_end(buf, "Connections");

    evhttp_add_header(req->output_headers, "Content-Type", "text/html");
    evhttp_send_reply(req, HTTP_OK, "OK", buf);
    evbuffer_free(buf);
}

void
httpd_put_addrs_html (struct evhttp_request *req, void *arg)
{
    struct evbuffer *buf;

    buf = evbuffer_new();
    httpd_put_html_start(buf, "Addresses");
    evbuffer_add_printf(buf, "var cols = [");
    evbuffer_add_printf(buf, "  {key:\"a\", label:\"Address\", sortable:true},");
    evbuffer_add_printf(buf, "  {key:\"c\", label:\"Connections\", sortable:true},");
    evbuffer_add_printf(buf, "  {key:\"t\", label:\"Timeout\", sortable:true},");
    evbuffer_add_printf(buf, "], data = [");
    g_hash_table_foreach(addr_table, (GHFunc) fill_http_addr_html, buf);
    httpd_put_html_end(buf, "Addresses");

    evhttp_add_header(req->output_headers, "Content-Type", "text/html");
    evhttp_send_reply(req, HTTP_OK, "OK", buf);
    evbuffer_free(buf);
}

void
httpd_put_hosts_html (struct evhttp_request *req, void *arg)
{
    struct evbuffer *buf;

    buf = evbuffer_new();
    httpd_put_html_start(buf, "Hosts");
    evbuffer_add_printf(buf, "var cols = [");
    evbuffer_add_printf(buf, "  {key:\"ip\", label:\"Address\", sortable:true},");
    evbuffer_add_printf(buf, "  {key:\"c\", label:\"Connections\", sortable:true},");
    evbuffer_add_printf(buf, "  {key:\"t\", label:\"Timeout\", sortable:true},");
    evbuffer_add_printf(buf, "  {key:\"u\", label:\"Host (40 char max)\", sortable:true},");
    evbuffer_add_printf(buf, "], data = [");
    g_hash_table_foreach(uri_table, (GHFunc) fill_http_urihost_html, buf);
    httpd_put_html_end(buf, "Hosts");

    evhttp_add_header(req->output_headers, "Content-Type", "text/html");
    evhttp_send_reply(req, HTTP_OK, "OK", buf);
    evbuffer_free(buf);
}

void
httpd_put_uris_html (struct evhttp_request *req, void *arg)
{
    struct evbuffer *buf;

    buf = evbuffer_new();
    httpd_put_html_start(buf, "URIs");
    evbuffer_add_printf(buf, "var cols = [");
    evbuffer_add_printf(buf, "  {key:\"ip\", label:\"Address\", sortable:true},");
    evbuffer_add_printf(buf, "  {key:\"c\", label:\"Connections\", sortable:true},");
    evbuffer_add_printf(buf, "  {key:\"t\", label:\"Timeout\", sortable:true},");
    evbuffer_add_printf(buf, "  {key:\"u\", label:\"URI (40 char max)\", sortable:true},");
    evbuffer_add_printf(buf, "], data = [");
    g_hash_table_foreach(uri_table, (GHFunc) fill_http_urihost_html, buf);
    httpd_put_html_end(buf, "URIs");

    evhttp_add_header(req->output_headers, "Content-Type", "text/html");
    evhttp_send_reply(req, HTTP_OK, "OK", buf);
    evbuffer_free(buf);
}

void
httpd_driver(struct evhttp_request *req, void *arg)
{
    struct evbuffer *buf;

    buf = evbuffer_new();

    evhttp_add_header(req->output_headers, "Content-Type", "text/plain");
    evbuffer_add_printf(buf, "Thrashd version: %s [%s]\n", VERSION,
                        process_name);

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
    evhttp_set_cb(httpd, "/holddowns.html", httpd_put_holddowns_html, NULL);
    evhttp_set_cb(httpd, "/config", httpd_put_config, NULL);
    evhttp_set_cb(httpd, "/connections", httpd_put_connections, NULL);
    evhttp_set_cb(httpd, "/connections.html", httpd_put_connections_html, NULL);
    evhttp_set_cb(httpd, "/addrs", httpd_put_addrs, NULL);
    evhttp_set_cb(httpd, "/addrs.html", httpd_put_addrs_html, NULL);
    evhttp_set_cb(httpd, "/uris", httpd_put_uris, NULL);
    evhttp_set_cb(httpd, "/uris.html", httpd_put_uris_html, NULL);
    evhttp_set_cb(httpd, "/hosts", httpd_put_hosts, NULL);
    evhttp_set_cb(httpd, "/hosts.html", httpd_put_hosts_html, NULL);
    evhttp_set_gencb(httpd, httpd_driver, NULL);
    return 0;
}
