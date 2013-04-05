/******************************************************************************/
/* bcast.c  -- Functions dealing with broadcasting events
 *
 * Copyright 2007-2013 AOL Inc. All rights reserved.
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <ctype.h>
#include "thrasher.h"
#include "event2/bufferevent.h"
#include "event2/bufferevent_struct.h"

extern int                syslog_enabled;
extern FILE              *logfile;

extern struct event_base *base;
extern uint16_t           bind_port;
extern gchar            **broadcasts;
extern char              *process_name;
struct ifaddrs           *ifaddr;
extern uint32_t           debug;


GHashTable     *broadcast_table;


void
thrash_bcast_init()
{
    broadcast_table = g_hash_table_new(g_str_hash, g_str_equal);
    if (getifaddrs(&ifaddr) == -1) {
        LOG(logfile, "Failed to get local ips %s", "");
    }
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

    if (broadcasts) {
        g_strfreev(broadcasts);
        broadcasts = 0;
    }
}

void thrash_bcast_event_cb(struct bufferevent *bev, short events, void *name)
{
    if (debug)
        LOG(logfile, "socket event %x for %s", events, (char*)name);

    if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
        bufferevent_free(bev);
        g_hash_table_remove(broadcast_table, name);
    }
}


struct bufferevent *
thrash_bcast_connect(char *nodename)
{
    char           *nodeptr = nodename;
    char            host[100];
    char            portstr[10];
    int             port = bind_port; 
    struct ifaddrs *ifa;

    while (*nodeptr && isspace(*nodeptr)) nodeptr++; // Remove leading spaces

    strncpy(host, nodeptr, sizeof(host));
    host[sizeof(host)-1] = 0;

    char *colon = strrchr(host, ':');
    if (colon) {
        *colon = 0;
        port = atoi(colon+1);
    }

    /* Lookup the ip address*/
    snprintf(portstr, sizeof(portstr), "%d", port);

    struct evutil_addrinfo hint;
    memset(&hint, 0, sizeof(hint));
    hint.ai_family   = AF_INET;
    hint.ai_protocol = IPPROTO_TCP;
    hint.ai_socktype = SOCK_STREAM;

    struct evutil_addrinfo *ai=NULL;

    evutil_getaddrinfo(host, portstr, &hint, &ai);
    if (!ai) {
        LOG(logfile, "Failed to resolve %s for %s", host, nodename);
        return 0;
    }

    /* Check to see if we are trying to connect to ourself by first checking the port and then our ips */
    if (port == bind_port) {
        for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
            if (ifa->ifa_addr == NULL || ifa->ifa_addr->sa_family != AF_INET)
                continue;

            if (((struct sockaddr_in *)ifa->ifa_addr)->sin_addr.s_addr == ((struct sockaddr_in *)ai->ai_addr)->sin_addr.s_addr) {
                *nodename = 0;
                evutil_freeaddrinfo(ai);
                return 0;
            }
        }
    }

    /* Connect to the server we want to broadcast to */
    struct bufferevent *be;
    be = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE);
    int r = bufferevent_socket_connect(be, ai->ai_addr, (int)ai->ai_addrlen);
    evutil_freeaddrinfo(ai);

    if (r != 0) {
        if (debug)
            LOG(logfile, "Couldn't connect to %s", nodename);
        bufferevent_free(be);
        return 0;
    }

    if (debug)
        LOG(logfile, "Connected to %s", nodename);

    bufferevent_setcb(be, NULL, NULL, thrash_bcast_event_cb, (void *)nodename);
    return be;
}

void
thrash_bcast_send(blocked_node_t *bnode)
{
    char     addrbuf[INET6_ADDRSTRLEN];
    char     buffer[1000];
    struct   bufferevent *be;
    int      i;
    int      blen;

    if (!broadcasts)
        return;

    int      plen = strlen(process_name);
    int      rlen = bnode->reason?strlen(bnode->reason):0;
    uint16_t n_rlen = htons(rlen + plen + 1);

    if (0) {
        buffer[0] = TYPE_INJECT_v2;
        memcpy(buffer+1, bnode->s6addr+12, 4);
        memcpy(buffer+5, &n_rlen, 2);
        memcpy(buffer+7, process_name, plen);
        buffer[7+plen] = ':';
        memcpy(buffer+7+plen+1, bnode->reason, rlen);
        blen = 7 + plen + 1 + rlen;
    } else {
        buffer[0] = TYPE_INJECT_v6;
        memcpy(buffer+1, &bnode->s6addr, 16);
        memcpy(buffer+17, &n_rlen, 2);
        memcpy(buffer+19, process_name, plen);
        buffer[19+plen] = ':';
        memcpy(buffer+19+plen+1, bnode->reason, rlen);
        blen = 19 + plen + 1 + rlen;
    }

    for (i = 0; broadcasts[i]; i++) {
        if (!*broadcasts[i])
            continue;

        be = g_hash_table_lookup(broadcast_table, broadcasts[i]);
        if (!be) {
            be = thrash_bcast_connect(broadcasts[i]);
            if (!be)
                continue;
            g_hash_table_insert(broadcast_table, broadcasts[i], be);
        }
        if (bufferevent_write(be, buffer, blen) >= 0) {
            if (debug)
                LOG(logfile, "Sending %s to %s (%d bytes)", inet_ntop(AF_INET6, bnode->s6addr, addrbuf, sizeof(addrbuf)), broadcasts[i], blen);
        } else {
            if (debug)
                LOG(logfile, "Failure sending %s to %s (%d bytes)", inet_ntop(AF_INET6, bnode->s6addr, addrbuf, sizeof(addrbuf)), broadcasts[i], blen);
            bufferevent_free(be);
            g_hash_table_remove(broadcast_table, broadcasts[i]);
        }
    }
}
