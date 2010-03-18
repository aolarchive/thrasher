#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include "thrasher.h"

int
thrash_bgp_connect(const char *sockname)
{
    int             sock;
    struct sockaddr_un sun;

    if ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
        return -1;

    memset(&sun, 0, sizeof(struct sockaddr_un));

    sun.sun_family = AF_UNIX;
    strncpy(sun.sun_path, sockname, sizeof(sun.sun_path));

    if (connect(sock, (struct sockaddr *) &sun, sizeof(sun)) < 0) {
        close(sock);
        return -1;
    }

    return sock;
}


static struct imsgbuf *
thrash_bgp_mk_inject_pkt(int sock, const uint32_t iaddr,
                         const bgp_community_t * community, const int type)
{
    struct network_config net;
    struct bgpd_addr addr;
    struct imsgbuf *ibuf;
    struct filter_set set;

    if (!(ibuf = malloc(sizeof(struct imsgbuf))))
        return NULL;

    memset(&addr, 0, sizeof(struct bgpd_addr));
    memset(&net, 0, sizeof(struct network_config));
    memset(&set, 0, sizeof(struct filter_set));

    addr.af = AF_INET;
    addr.v4.s_addr = iaddr;

    memcpy(&net.prefix, &addr, sizeof(struct bgpd_addr));
    net.prefixlen = 32;

    if (community) {
        set.action.community.as = community->asn;
        set.action.community.type = community->community;
        set.type = ACTION_SET_COMMUNITY;
    }

    imsg_init(ibuf, sock);

    imsg_compose(ibuf, type, 0, 0, -1, &net, sizeof(net));

    if (community)
        imsg_compose(ibuf, IMSG_FILTER_SET,
                     0, 0, -1, &set, sizeof(struct filter_set));

    imsg_compose(ibuf, IMSG_NETWORK_DONE, 0, 0, -1, NULL, 0);

    return ibuf;
}

void
thrash_bgp_freepkt(struct imsgbuf *buf)
{
    imsg_clear(buf);
    free(buf);
}

int
thrash_bgp_inject(const uint32_t addr,
                  const bgp_community_t * community, int sock)
{
    struct imsgbuf *buf;

    buf =
        thrash_bgp_mk_inject_pkt(sock, addr, community, IMSG_NETWORK_ADD);

    if (msgbuf_write(&buf->w) < 0)
        return -1;

    thrash_bgp_freepkt(buf);
    return 0;
}

#ifdef TEST_BGP
int
main(int argc, char **argv)
{
    int             sock;
    uint16_t        asn;
    uint32_t        addr;
    bgp_community_t *community = NULL;

    if (argc < 2) {
        printf("Usage: %s <addr> [<asn> <community>]\n", argv[0]);
        exit(1);
    }

    addr = (uint32_t) inet_addr(argv[1]);

    if (argv[2] && argv[3]) {
        community = malloc(sizeof(bgp_community_t));

        community->asn = atoi(argv[2]);
        community->community = atoi(argv[3]);
    }

    sock = thrash_bgp_connect("/var/run/bgpd.sock");

    printf("%s\n",
           thrash_bgp_inject(addr, community, sock) ?
           "unsuccessful" : "successful");

    if (community)
        free(community);

    return 0;
}
#endif
