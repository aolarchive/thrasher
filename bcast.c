#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include "thrasher.h"
#include "event2/bufferevent.h"
#include "event2/bufferevent_struct.h"

extern struct event_base *base;
extern uint16_t           bind_port;
extern gchar            **broadcasts;
extern char              *process_name;



GHashTable     *broadcast_table;


void
thrash_bcast_init()
{
    broadcast_table = g_hash_table_new(g_str_hash, g_str_equal);
}

void
thrash_bcast_reset()
{
    GHashTableIter iter;
    gpointer key, value;
    g_hash_table_iter_init (&iter, broadcast_table);

    while (g_hash_table_iter_next (&iter, &key, &value)) 
    {
        bufferevent_free(value);
        g_hash_table_iter_remove(&iter);
    }
}

void thrash_bcast_event_cb(struct bufferevent *bev, short events, void *name)
{
    if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
        bufferevent_free(bev);
        g_hash_table_remove(broadcast_table, name);
    }
}


struct bufferevent *
thrash_bcast_connect(const char *nodename)
{
    char host[100];
    int port = bind_port; 

    strncpy(host, nodename, sizeof(host));
    host[sizeof(host)-1] = 0;

    char *colon = strrchr(host, ':');
    if (colon >= 0) {
        *colon = 0;
        port = atoi(colon+1);
    }

    /* Don't send back to ourselves */
    if (strcmp(host, "localhost") == 0 && port == bind_port)
        return 0;

    struct bufferevent *be;
    be = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE);
    int r = bufferevent_socket_connect_hostname(be, NULL, AF_UNSPEC, host, port);

    if (r == 0) {
        bufferevent_setcb(be, NULL, NULL, thrash_bcast_event_cb, (void *)nodename);
        return be;
    }
    
    bufferevent_free(be);
    return 0;
}

void
thrash_bcast_send(blocked_node_t *bnode)
{
    char     buffer[1000];
    struct   bufferevent *be;
    int      i;

    if (!broadcasts)
        return;

    int      plen = strlen(process_name);
    int      rlen = bnode->reason?strlen(bnode->reason):0;
    uint16_t n_rlen = htons(rlen + plen + 1);

    buffer[0] = TYPE_INJECT_v2;
    memcpy(buffer+1, &bnode->saddr, 4);
    memcpy(buffer+5, &n_rlen, 2);
    memcpy(buffer+7, process_name, plen);
    buffer[7+plen] = ':';
    memcpy(buffer+7+plen+1, bnode->reason, rlen);

    for (i = 0; broadcasts[i]; i++) {
        be = g_hash_table_lookup(broadcast_table, broadcasts[i]);
        if (!be) {
            be = thrash_bcast_connect(broadcasts[i]);
            if (!be)
                continue;
            g_hash_table_insert(broadcast_table, broadcasts[i], be);
        }
        i = bufferevent_write(be, buffer, 7 + plen + 1 + rlen);
    }


}
