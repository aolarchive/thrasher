#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include "bgpd.h"

#define SOCKET_NAME     "/var/run/bgpd.sock"

typedef struct _bgp_community {
    uint8_t asn;
    uint8_t community;
} bgp_community_t;

typedef struct _thrash_bgp {
    uint32_t addr;
    bgp_community_t community;
    char *sockname;
    int   sock;
    iov_t *iov;
    struct event event;
} thrash_bgp_t;

int 
thrash_bgp_connect(thrash_bgp_t *bgp)
{
    int sock;



int main(int argc, char **argv)
{
    int fd;
    struct sockaddr_un sun;
    struct network_config net;
    struct bgpd_addr addr;
    struct in_addr ina;
    struct imsgbuf *ibuf;

    char *toinject = argv[1];

    if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
	exit(1);

    bzero(&sun, sizeof(sun));

    sun.sun_family = AF_UNIX;
    strcpy(sun.sun_path, SOCKET_NAME); 

    connect(fd, (struct sockaddr *)&sun, sizeof(sun));

    inet_net_pton(AF_INET, toinject, &ina, sizeof(ina));

    bzero(&addr, sizeof(addr));
    addr.af = AF_INET;
    addr.v4 = ina;


    bzero(&net, sizeof(net));
    memcpy(&net.prefix, &addr, sizeof(struct bgpd_addr));

    net.prefixlen = 32;
    
    struct filter_set set;
    memset(&set, 0, sizeof(set));
    set.action.community.as = 666;
    set.action.community.type = 30;
    set.type = ACTION_SET_COMMUNITY;

    ibuf = malloc(sizeof(struct imsgbuf));
    imsg_init(ibuf, fd);

    imsg_compose(ibuf, IMSG_NETWORK_ADD,  0, 0, -1, &net, sizeof(net));
    imsg_compose(ibuf, IMSG_FILTER_SET, 0, 0, -1, &set, sizeof(struct filter_set));
    imsg_compose(ibuf, IMSG_NETWORK_DONE, 0, 0, -1, NULL, 0);

    /*
    msgbuf_write(&ibuf->w);
    */

    char *sendbuf = malloc(1024);
    struct buf *buf;
    int offset = 0;
    memset(sendbuf, 0, 1024);

    TAILQ_FOREACH(buf, &ibuf->w.bufs, entry) {
	int len = buf->wpos - buf->rpos;
	char *base = buf->buf + buf->rpos;
	printf("%d %d\n", offset, len);
	memcpy(&sendbuf[offset], base, len);
	offset += len;
    }

    printf("Total len: %d\n", offset);
    write(fd, sendbuf, offset);
    imsg_clear(ibuf);
    free(ibuf);
    free(sendbuf);
    return 0;
}
	





