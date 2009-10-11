#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <getopt.h>
#include <assert.h>
#include <errno.h>
#include <sys/sysinfo.h>
#define __FAVOR_BSD
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <net/ethernet.h>
#include <syslog.h>
#include <glib.h>
#include <sys/queue.h>
#include <event.h>
#include <evhttp.h>
#include <evdns.h>
#include "iov.h"

#define LOG(x,s...) do { \
    if (!syslog_enabled) { \
      time_t t = time(NULL); \
      char *d = ctime(&t); \
      fprintf(stderr,"%.*s %s[%d] %s(): ",\
            (int)strlen(d)-1,d, __FILE__,\
            __LINE__,__FUNCTION__); \
      fprintf(stderr,x,## s); \
      fprintf(stderr,"\n");\
    } else { \
      syslog(LOG_NOTICE, x, ## s); \
    } \
} while(0);

typedef enum {
    TYPE_THRESHOLD_v1 = 0, 
    TYPE_REMOVE,
    TYPE_INJECT,
    TYPE_THRESHOLD_v2
} thrash_pkt_type;

/***************************************
 * Client structures                   *
 **************************************/
typedef struct thrash_cfg {
		uint8_t  pkt_type;
    char    *thrashd_addr; 
		uint16_t thrashd_port;
} thrash_clicfg_t;

typedef struct thrash_clisock {
		thrash_clicfg_t *cfg;
		int                  sock;
		uint8_t              connected;
		iov_t               *iov_data;
		void                *args;
} thrash_clisock_t;

/***************************************
 * Server structures                   *
 ***************************************/
typedef struct block_ratio {
    uint32_t        num_connections;
    uint32_t        timelimit;
} block_ratio_t;

typedef struct query {
    uint32_t        saddr;
    uint16_t        host_len;
    uint16_t        uri_len;
    char           *host;
    char           *uri;
} query_t;

typedef struct client_conn {
    uint32_t        conn_addr;
    uint16_t        conn_port;
    int             sock;
    iov_t           data;
    query_t         query;
    uint8_t         type;
    struct event    event;
} client_conn_t;

typedef struct svrconn_t {
    uint32_t        conn_addr;
    uint16_t        conn_port;
    int             sock;
    iov_t           data;
    query_t         query;
    uint8_t         type;
    struct event    event;
} conn_t;

typedef struct qstats {
    char           *key;
    uint32_t        saddr;
    uint32_t        connections;
    GHashTable     *table;
    struct event    timeout;
} qstats_t;

typedef struct blocked_node {
    uint32_t        saddr;
    uint32_t        count;
    uint32_t        first_seen_addr;
    struct event    timeout;
} blocked_node_t;

typedef struct rbl_negcache {
    uint32_t        addr;
    struct event    timeout;
} rbl_negcache_t;

typedef enum {
    stat_type_uri,
    stat_type_host,
    stat_type_address
} stat_type_t;

/***************************************
 * Client functions                    *
 ***************************************/
thrash_clicfg_t  *cli_cfg_init(void);
thrash_clisock_t *cli_sock_init(void);
int  clicfg_reset(thrash_clicfg_t *cfg);
void clicfg_set_type(thrash_clicfg_t *cfg, thrash_pkt_type type); 
void clicfg_set_addr(thrash_clicfg_t *cfg, char *addr);
void clicfg_set_port(thrash_clicfg_t *cfg, uint16_t port);
int  clisock_reset(thrash_clisock_t *sock);
int  cliconnect(thrash_clisock_t *sock);
int  clidisconnect(thrash_clisock_t *sock);

/***************************************
 * Server functions                    *
 ***************************************/
void reset_query(query_t * query);
void free_client_conn(client_conn_t * conn);
int  uint32_cmp(const void *a, const void *b);
int  set_nb(int sock);

void rbl_init(void);
void expire_rbl_negcache(int sock, short which, rbl_negcache_t * rnode);
void get_rbl_answer(int result, char type, int count, int ttl, struct in_addr *addresses, uint32_t * arg);

void make_rbl_query(uint32_t addr);

void remove_holddown(uint32_t addr);
void expire_bnode(int sock, short which, blocked_node_t * bnode);
void expire_stats_node(int sock, short which, qstats_t * stat_node);
blocked_node_t *block_addr(client_conn_t * conn, qstats_t * stats);
int update_thresholds(client_conn_t * conn, char *key, stat_type_t type);
int do_thresholding(client_conn_t * conn);

void client_process_data(int sock, short which, client_conn_t * conn);
void client_read_payload(int sock, short which, client_conn_t * conn);
void client_read_v2_header(int sock, short which, client_conn_t * conn);
void client_read_v1_header(int sock, short which, client_conn_t * conn);
void client_read_injection(int sock, short which, client_conn_t * conn);
void client_read_type(int sock, short which, client_conn_t * conn);

void fill_current_connections(client_conn_t * conn, struct evbuffer *buf);
gboolean fill_http_blocks(void *key, blocked_node_t * val, struct evbuffer *buf);
void httpd_put_hips(struct evhttp_request *req, void *args);
void httpd_put_connections(struct evhttp_request *req, void *args);
void httpd_put_config(struct evhttp_request *req, void *args);
void httpd_driver(struct evhttp_request *req, void *arg);

void server_driver(int sock, short which, void *args);
int server_init(void);
int webserver_init(void);
void qps_init(void);

void qps_reset(int sock, int which, void *args);
void syslog_init(char *facility);
void daemonize(const char *path);
