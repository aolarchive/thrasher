/*
 * this is an example module that interacts with the thrasher daemon 
 */
/*
 * this isn't tested in production, so you have been warned 
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <unistd.h>
#include "httpd.h"
#include "http_core.h"
#include "apr_pools.h"
#include "apr_tables.h"
#include "http_protocol.h"
#include "http_config.h"
#include "http_log.h"
#include "apr_hash.h"
#include "apr_strings.h"
#include "http_request.h"
#include "apr_reslist.h"
#include "apr_thread_rwlock.h"
#include "apr_network_io.h"
#include "version.h"

module AP_MODULE_DECLARE_DATA thrasher_module;

typedef struct thrasher_config {
    char           *thrashd_host;
    int             thrashd_port;
} thrasher_config_t;

typedef struct thrasher_conn {
    apr_pool_t     *pool;
    apr_socket_t   *sock;
#ifdef APR_HAS_THREADS
    apr_thread_mutex_t *mutex;
#endif
} thrasher_conn_t;

#define TKEY "thrasher_conn_config"

apr_status_t    thrasher_connect(thrasher_conn_t * tconn,
                                 thrasher_config_t * config);

static int
thrasher_handler(request_rec * rec)
{
    int             ret;
    apr_status_t    rv;
    thrasher_conn_t *tconn;
    thrasher_config_t *config;

    ret = DECLINED;

    config = ap_get_module_config(rec->server->module_config,
                                  &thrasher_module);

    apr_pool_userdata_get((void **) &tconn,
                          TKEY, rec->server->process->pool);

#ifdef APR_HAS_THREADS
    apr_thread_mutex_lock(tconn->mutex);
#endif

    uint8_t         type = 0;
    uint32_t        srcaddr = inet_addr(rec->connection->remote_ip);
    uint16_t        uri_len = htons(strlen(rec->uri));
    uint16_t        host_len = htons(strlen(rec->hostname));

    struct iovec    vec[6];

    vec[0].iov_base = &type;
    vec[0].iov_len = 1;
    vec[1].iov_base = &srcaddr;
    vec[1].iov_len = sizeof(uint32_t);
    vec[2].iov_base = &uri_len;
    vec[2].iov_len = sizeof(uint16_t);
    vec[3].iov_base = &host_len;
    vec[3].iov_len = sizeof(uint16_t);
    vec[4].iov_base = rec->uri;
    vec[4].iov_len = strlen(rec->uri);
    vec[5].iov_base = (char *) rec->hostname;
    vec[5].iov_len = strlen(rec->hostname);

    apr_size_t      sent;

    apr_socket_sendv(tconn->sock, vec, 6, &sent);

    uint8_t         resp;

    rv = apr_socket_recv(tconn->sock, &resp, &sent);

    do {
        if (APR_STATUS_IS_TIMEUP(rv)) {
            apr_socket_close(tconn->sock);
            thrasher_connect(tconn, config);
            ret = DECLINED;
            break;
        }
        if (APR_STATUS_IS_EOF(rv) || sent == 0) {
            apr_socket_close(tconn->sock);
            thrasher_connect(tconn, config);
            ret = DECLINED;
            break;
        }
        if (resp) {
            ret = 403;
            break;
        }
    } while (0);

#ifdef APR_HAS_THREADS
    apr_thread_mutex_unlock(tconn->mutex);
#endif
    return ret;
}

apr_status_t
thrasher_connect(thrasher_conn_t * tconn, thrasher_config_t * config)
{

    apr_sockaddr_t *sockaddr;

    apr_sockaddr_info_get(&sockaddr,
                          config->thrashd_host, APR_INET,
                          config->thrashd_port, 0, tconn->pool);

    apr_socket_create(&tconn->sock, sockaddr->family,
                      SOCK_STREAM, APR_PROTO_TCP, tconn->pool);
    apr_socket_timeout_set(tconn->sock, 500000);
    apr_socket_connect(tconn->sock, sockaddr);

    return APR_SUCCESS;
}

static void
thrasher_child_init(apr_pool_t * pool, server_rec * rec)
{
    thrasher_config_t *config;
    thrasher_conn_t *tconn;
    apr_status_t    rv;

    config = ap_get_module_config(rec->module_config, &thrasher_module);
    ap_assert(config);

    /*
     * create the connection structure 
     */
    tconn = apr_pcalloc(pool, sizeof(thrasher_conn_t));
    ap_assert(tconn);

    tconn->pool = pool;

    /*
     * create our socket mutex 
     */
    rv = apr_thread_mutex_create(&tconn->mutex,
                                 APR_THREAD_MUTEX_DEFAULT, pool);
    ap_assert(rv == APR_SUCCESS);

    /*
     * connect to the thrashd instance 
     */
    thrasher_connect(tconn, config);

    apr_pool_userdata_set(tconn, TKEY,
                          apr_pool_cleanup_null, rec->process->pool);
}

static void    *
thrasher_init_config(apr_pool_t * pool, server_rec * svr)
{
    thrasher_config_t *config;
    const char     *userdata = "thrasher_config";
    void           *done;

    apr_pool_userdata_get(&done, userdata, svr->process->pool);

    if (!done) {
        apr_pool_userdata_set((void *) 1,
                              userdata, apr_pool_cleanup_null,
                              svr->process->pool);
        return OK;
    }

    config =
        (thrasher_config_t *) apr_pcalloc(svr->process->pool,
                                          sizeof(*config));

    return config;
}


static const char *
cmd_thrasher_host(cmd_parms * cmd, void *dummy_config, const char *arg)
{
    thrasher_config_t *config;

    config = ap_get_module_config(cmd->server->module_config,
                                  &thrasher_module);

    ap_assert(config);

    config->thrashd_host = apr_pstrdup(cmd->pool, arg);

    return NULL;
}

static const char *
cmd_thrasher_port(cmd_parms * cmd, void *dummy_config, const char *arg)
{
    thrasher_config_t *config;
    config = ap_get_module_config(cmd->server->module_config,
                                  &thrasher_module);
    ap_assert(config);

    config->thrashd_port = atoi(arg);
    return NULL;
}

const command_rec thrasher_directives[] = {
    AP_INIT_TAKE1("thrasher_host", cmd_thrasher_host,
                  NULL, RSRC_CONF,
                  "The hostname of the thrashd instance to connect to"),
    AP_INIT_TAKE1("thrasher_port", cmd_thrasher_port,
                  NULL, RSRC_CONF,
                  "The port of the thrashd instance"),
    {NULL}
};

static void
thrasher_hooker(apr_pool_t * pool)
{
    static const char *beforeme[] = {
        "mod_webfw2.c",
        NULL
    };

    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, NULL,
                 "initializing mod_thrasher v%s", VERSION);
    ap_hook_child_init(thrasher_child_init, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_access_checker(thrasher_handler, beforeme,
                           NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA thrasher_module = {
    STANDARD20_MODULE_STUFF,
    NULL,
    NULL,
    thrasher_init_config,
    NULL,
    thrasher_directives,
    thrasher_hooker
};
