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
#include <signal.h>
#define __FAVOR_BSD
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <glib.h>
#include <sys/queue.h>
#include <event2/event.h>
#include <event2/event_struct.h>
#include <event2/buffer.h>
#include <event2/http.h>
#include <event2/dns.h>
#include <sys/types.h>
#ifdef WITH_BGP
#include "bgp.h"
#endif

#include "iov.h"
#include "rbl.h"

#if 0
#define LOG(f, x, s...) do { \
    if (syslog_enabled) {\
    	syslog(LOG_NOTICE, x, ##, s); }\
    else {\
      	time_t t = time(NULL); \
      	char *d = ctime(&t); \
      	fprintf(f,"%.*s %s[%d] %s(): ",\
            (int)strlen(d)-1,d, __FILE__,\
            __LINE__,__FUNCTION__); \
      	fprintf(f,x,## s); \
      	fprintf(f,"\n");\
    } \
} while(0) /* no trailing ; */
#endif

#define LOG(f, x, ...) do { \
    if (syslog_enabled) {\
        syslog(LOG_NOTICE, x,  __VA_ARGS__); }\
    else {\
        time_t t = time(NULL); \
        char *d = ctime(&t); \
        fprintf(f,"%.*s %s[%d] %s(): ",\
            (int)strlen(d)-1,d, __FILE__,\
            __LINE__,__FUNCTION__); \
        fprintf(f,x,__VA_ARGS__); \
        fprintf(f,"\n");\
	fflush(f); \
    } \
} while(0) /* no trailing ; */

typedef enum {
    TYPE_THRESHOLD_v1 = 0, 
    TYPE_REMOVE,
    TYPE_INJECT,
    TYPE_THRESHOLD_v2,
    TYPE_THRESHOLD_v3,
    TYPE_THRESHOLD_v4,
    TYPE_INJECT_v2 = 100
} thrash_pkt_type;

/***************************************
 * Client structures                   *
 **************************************/
typedef struct thrash_resp { 
    uint8_t permit; 
    uint32_t ident; 
} thrash_resp_t;

typedef struct thrash_client {
    char              *host;
    uint16_t           port;
    int                sock;
    thrash_pkt_type    type;
    iov_t              data;
    uint32_t           addr_lookup;
    void              *userdata;
    struct event_base *evbase;
    struct event       event;
    void (*resp_cb) (struct thrash_client *cli, thrash_resp_t *resp);
} thrash_client_t;


typedef struct query client_query_t;

/***************************************
 * Server structures                   *
 ***************************************/
typedef struct block_ratio {
    uint16_t        num_connections;
    uint16_t        timelimit;
} block_ratio_t;

typedef struct query {
    uint32_t        saddr;
    uint16_t        host_len;
    uint16_t        uri_len;
    uint16_t        reason_len;
    uint32_t        ident;
    char           *host;
    char           *uri;
    char           *reason;
} query_t;

typedef struct client_conn {
    uint64_t        requests;
    time_t          conn_time;
    struct timeval  last_time;
    uint32_t        conn_addr;
    uint16_t        conn_port;
    int             sock;
    iov_t           data;
    query_t         query;
    uint8_t         type;
    uint32_t        id;
    struct event    event;
    struct event    timeout;
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
    GHashTable     *table;
    char           *key;
    char           *reason;
    struct event    timeout;
    uint32_t        saddr;
    uint32_t        connections;
} qstats_t;

typedef struct blocked_node {
    struct timeval  last_time;
    double          avg_distance_usec;
    char           *reason;
    uint32_t        saddr;
    uint32_t        count;
    uint32_t        first_seen_addr;
    block_ratio_t   ratio;
    struct event    timeout;
    struct event    hard_timeout;
    struct event    recent_block_timeout;
} blocked_node_t;

typedef enum {
    stat_type_uri,
    stat_type_host,
    stat_type_address
} stat_type_t;

/***************************************
 * Client functions                    *
 ***************************************/
#define thrash_client_sethost(a,b) do { a->host = strdup(b); } while(0);
#define thrash_client_setport(a,b) do { a->port = b; } while(0);
#define thrash_client_settype(a,b) do { a->type = b; } while(0);
#define thrash_client_setsock(a,b) do { a->sock = b; } while(0);
#define thrash_client_setevbase(a,b) do { a->evbase = b; \
    event_base_set(b, &a->event); } while(0);
#define thrash_client_setident(a,b) do { a->ident = b; } while(0);

thrash_client_t * init_thrash_client(struct event_base *b);
int thrash_client_connect(thrash_client_t *cli);
void thrash_client_read_resp(int sock, short which, thrash_client_t *cli);
void thrash_client_write(int sock, short which, thrash_client_t *cli);
void thrash_client_lookup(thrash_client_t *cli, uint32_t addr, void *data);

/***************************************
 * Server functions                    *
 ***************************************/
void reset_query(query_t * query);
void free_client_conn(client_conn_t * conn);
int  uint32_cmp(const void *a, const void *b);
int  set_nb(int sock);

void remove_holddown(uint32_t addr);
void expire_bnode(int sock, short which, blocked_node_t * bnode);
void expire_recent_bnode(int sock, short which, blocked_node_t *bnode);
void expire_stats_node(int sock, short which, qstats_t * stat_node);
blocked_node_t *block_addr(client_conn_t * conn, uint32_t addr, const char *reason);
int update_thresholds(client_conn_t * conn, const char *key, stat_type_t type, block_ratio_t *ratio);
int do_thresholding(client_conn_t * conn);
void save_data();
void load_config(gboolean reload);

void client_process_data(int sock, short which, client_conn_t * conn);
void client_read_payload(int sock, short which, client_conn_t * conn);
void client_read_v3_header(int sock, short which, client_conn_t * conn);
void client_read_v2_header(int sock, short which, client_conn_t * conn);
void client_read_v1_header(int sock, short which, client_conn_t * conn);
void client_read_injection(int sock, short which, client_conn_t * conn);
void client_read_type(int sock, short which, client_conn_t * conn);


void server_driver(int sock, short which, void *args);
int server_init(void);
void qps_init(void);

void qps_reset(int sock, int which, void *args);
void syslog_init(char *facility);
void daemonize(const char *path);

uint32_t event_remaining_seconds(struct event *ev);
const char *blankprint(const char *str);

/***************************************
 * bcast functions                     *
 ***************************************/

void thrash_bcast_init();
void thrash_bcast_reset();
void thrash_bcast_send(blocked_node_t *bnode);
