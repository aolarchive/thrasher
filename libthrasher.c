/******************************************************************************/
/* libthrasher.c  -- Simple client library to thrasher
 *
 * Copyright 2007-2013 AOL Inc. All rights reserved.
 *
 */
#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include "iov.h"
#include "thrasher.h"


static struct event_base *base;

thrash_client_t *
init_thrash_client(struct event_base *b)
{
    thrash_client_t *ret;

    base = b;

    ret = malloc(sizeof(*ret));

    ret->host = NULL;
    ret->port = 1972;
    ret->sock = 0;
    ret->type = TYPE_THRESHOLD_v1;
    memset(&ret->data, 0, sizeof(iov_t));
    memset(&ret->event, 0, sizeof(struct event));

    return ret;
}

int
thrash_client_connect(thrash_client_t * cli)
{
    struct sockaddr_in inaddr;
    uint32_t        addr;
    int             sock;

    if (!cli || !cli->host)
        return -1;

    addr = inet_addr(cli->host);
    inaddr.sin_family = AF_INET;
    inaddr.sin_addr.s_addr = addr;
    inaddr.sin_port = htons(cli->port);

    if ((sock = socket(PF_INET, SOCK_STREAM, 0)) <= 0) {
        printf("Sockerr: %s\n", strerror(errno));
        return -1;
    }

    if (connect(sock, (struct sockaddr *) &inaddr, sizeof(inaddr))) {
        printf("Connerr: %s\n", strerror(errno));
        return -1;
    }

    if (fcntl(sock, F_SETFL, fcntl(sock, F_GETFL, 0) | O_NONBLOCK)) {
        printf("Sockerr: %s\n", strerror(errno));
        return -1;
    }

    thrash_client_setsock(cli, sock);

    return 0;
}

void
thrash_client_read_resp(int sock, short which, thrash_client_t * cli)
{
    uint8_t         resp;
    int             bytes_read;
    thrash_resp_t  *tresp;

    tresp = malloc(sizeof(*tresp));
    assert(tresp != NULL);

    if (cli->type == TYPE_THRESHOLD_v3 ||
        cli->type == TYPE_THRESHOLD_v4) {
        char           data[5];

        bytes_read = recv(sock, data, 5, 0);
        assert(bytes_read == 5);

        /*
         * copy over the identifier for v3 packets 
         */
        memcpy(&tresp->ident, data, 4);
        memcpy(&tresp->permit, &data[4], 1);
    } else if (cli->type == TYPE_INJECT || cli->type == TYPE_INJECT_v2 || cli->type == TYPE_REMOVE) {
    } else {
        bytes_read = recv(sock, &resp, 1, 0);
        assert(bytes_read == 1);
        tresp->permit = resp;
    }

    cli->resp_cb(cli, tresp);
}

void
thrash_client_write(int sock, short which, thrash_client_t * cli)
{
    int             ioret;

    ioret = write_iov(&cli->data, sock);

    if (ioret < 0) {
        printf("Lost connection to %s (%s)\n", cli->host, strerror(errno));
        exit(1);
    }

    if (ioret > 0) {
        event_assign(&cli->event, base, sock, EV_WRITE,
                  (void *) thrash_client_write, cli);
        event_add(&cli->event, 0);
    }

    reset_iov(&cli->data);

    if (cli->type == TYPE_INJECT || cli->type == TYPE_INJECT_v2 || cli->type == TYPE_REMOVE) {
        cli->resp_cb(cli, NULL);
        return;
    }

    event_assign(&cli->event, base, sock, EV_READ,
              (void *) thrash_client_read_resp, (void *) cli);
    event_add(&cli->event, 0);
}

client_query_t *
create_v1_query(const char *host, const char *uri)
{
    client_query_t *query;

    query = malloc(sizeof(*query));

    if (!query)
        return NULL;

    query->host = NULL;
    query->host_len = 0;
    query->uri = NULL;
    query->uri_len = 0;

    if (host) {
        query->host = strdup(host);
        query->host_len = strlen(host);
    }
    if (uri) {
        query->uri = strdup(uri);
        query->uri_len = strlen(uri);
    }

    return query;
}

#define create_v2_query() do { create_v1_query(NULL, NULL) } while(0);

client_query_t *
create_v3_query(const char *host, const char *uri, uint32_t id)
{
    client_query_t *query;


    query = create_v1_query(host, uri);

    if (!query)
        return NULL;

    query->ident = id;

    return query;
}

void
thrash_client_lookup(thrash_client_t * cli, uint32_t addr, void *data)
{
    client_query_t *q;
    uint16_t        hlen,
                    ulen,
                    rlen;
    uint32_t        ident;

    q = (client_query_t *) data;

    if (!cli)
        return;

    switch (cli->type) {

    case TYPE_THRESHOLD_v1:
        /*
         * data will be a client_query_t 
         */
        if (!q)
            return;

        hlen = htons(q->host_len);
        ulen = htons(q->uri_len);

        initialize_iov(&cli->data,
                       sizeof(uint32_t) +
                       sizeof(uint16_t) +
                       sizeof(uint16_t) + q->host_len + q->uri_len + 1);

        memcpy(cli->data.buf, &cli->type, 1);
        memcpy(&cli->data.buf[1], &addr, sizeof(uint32_t));
        memcpy(&cli->data.buf[5], &hlen, sizeof(uint16_t));
        memcpy(&cli->data.buf[7], &ulen, sizeof(uint16_t));
        memcpy(&cli->data.buf[9], q->host, q->host_len);
        memcpy(&cli->data.buf[9 + q->host_len], q->uri, q->uri_len);
        break;
    case TYPE_REMOVE:
    case TYPE_INJECT:
    case TYPE_THRESHOLD_v2:
        /*
         * [uint8_t type][uint32_t addr] 
         */
        initialize_iov(&cli->data, 5);
        memcpy(cli->data.buf, &cli->type, 1);
        memcpy(&cli->data.buf[1], &addr, 4);
        break;
    case TYPE_INJECT_v2 :
        rlen = htons(q->reason_len);

        initialize_iov(&cli->data, 7 + q->reason_len);

        memcpy(cli->data.buf, &cli->type, 1);
        memcpy(&cli->data.buf[1], &addr, 4);
        memcpy(&cli->data.buf[5], &rlen, sizeof(uint16_t));
        memcpy(&cli->data.buf[7], q->reason, q->reason_len);
        break;
    case TYPE_THRESHOLD_v3:
        if (!q)
            return;

        hlen = htons(q->host_len);
        ulen = htons(q->uri_len);
        ident = htonl(q->ident);

        initialize_iov(&cli->data, sizeof(uint8_t) +    // type
                       sizeof(uint32_t) +       // identifier
                       sizeof(uint32_t) +       // address
                       sizeof(uint16_t) +       // hostlen
                       sizeof(uint16_t) +       // urilen
                       q->host_len + q->uri_len);

        memcpy(cli->data.buf, &cli->type, 1);
        memcpy(&cli->data.buf[1], &q->ident, sizeof(uint32_t));
        memcpy(&cli->data.buf[5], &addr, sizeof(uint32_t));
        memcpy(&cli->data.buf[9], &hlen, sizeof(uint16_t));
        memcpy(&cli->data.buf[11], &ulen, sizeof(uint16_t));
        memcpy(&cli->data.buf[13], q->host, q->host_len);
        memcpy(&cli->data.buf[13 + q->host_len], q->uri, q->uri_len);
        break;

    case TYPE_THRESHOLD_v4:
        if (!q)
            return;

        hlen = htons(q->host_len);
        ulen = htons(q->uri_len);
        rlen = htons(q->reason_len);
        ident = htonl(q->ident);

        initialize_iov(&cli->data, sizeof(uint8_t) +    // type
                       sizeof(uint32_t) +       // identifier
                       sizeof(uint32_t) +       // address
                       sizeof(uint16_t) +       // hostlen
                       sizeof(uint16_t) +       // urilen
                       sizeof(uint16_t) +       // reasonlen
                       q->host_len + q->uri_len + q->reason_len);

        memcpy(cli->data.buf, &cli->type, 1);
        memcpy(&cli->data.buf[1], &rlen, sizeof(uint16_t));
        memcpy(&cli->data.buf[3], &q->ident, sizeof(uint32_t));
        memcpy(&cli->data.buf[7], &addr, sizeof(uint32_t));
        memcpy(&cli->data.buf[11], &hlen, sizeof(uint16_t));
        memcpy(&cli->data.buf[13], &ulen, sizeof(uint16_t));
        memcpy(&cli->data.buf[15], q->host, q->host_len);
        memcpy(&cli->data.buf[15 + q->host_len], q->uri, q->uri_len);
        memcpy(&cli->data.buf[15 + q->host_len + q->uri_len], q->reason, q->reason_len);
        break;

    case TYPE_THRESHOLD_v6:
    case TYPE_INJECT_v6 :
    case TYPE_REMOVE_v6 :
        break;

    }

    cli->addr_lookup = addr;

    event_assign(&cli->event, base, cli->sock, EV_WRITE,
              (void *) thrash_client_write, cli);
    event_add(&cli->event, 0);
}

void
free_thrash_client(thrash_client_t * cli)
{
    if (!cli)
        return;

    close(cli->sock);
    reset_iov(&cli->data);
    free(cli);
}

void
free_thrash_resp(thrash_resp_t * resp)
{
    free(resp);
}

#ifdef LIBTHRASHER_MAIN

void
resp_callback(thrash_client_t * cli, thrash_resp_t * resp)
{
    if (!resp) {
        printf("odd response, got null\n");
        return;
    }

    if (resp->permit)
        printf("%u is blocked!\n", cli->addr_lookup);
    else
        printf("%u is not blocked\n", cli->addr_lookup);


    event_base_loopbreak(cli->evbase);
    free_thrash_resp(resp);
}


int
main(int argc, char **argv)
{
    uint32_t        i;
    struct event_base *evbase;

    evbase = event_init();

    thrash_client_t *lc;
    lc = init_thrash_client(evbase);
    lc->evbase = evbase;
    lc->resp_cb = resp_callback;
    thrash_client_sethost(lc, "127.0.0.1");
    thrash_client_settype(lc, TYPE_THRESHOLD_v1);
    thrash_client_connect(lc);

    for (i = 0; i < 30; i++) {
        client_query_t *query;

        printf("pkt:%d ", i);

        query = create_v1_query("abc", "/");
        thrash_client_lookup(lc, i, query);
        event_base_loop(evbase, 0);
    }

    free_thrash_client(lc);

    return 0;
}
#endif
