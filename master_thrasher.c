#include <stdint.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include "thrasher.h"

static thrash_pkt_type pkt_type;
static char           *thrashd_host;
static int             thrashd_port;

void
globals_init(void)
{
    pkt_type = TYPE_INJECT;
    thrashd_host = "127.0.0.1";
    thrashd_port = 1972;
}

static char help[] =
    " -i: INJECT Addr\n"
    " -r: REMOVE Addr\n" " -s <thrashd addr>\n" " -p <thrashd port>\n";

int
parse_args(int argc, char **argv)
{
    int c;
    int jmp = 1;

    while ((c = getopt(argc, argv, "irs:p:h")) != -1) {
        switch (c) {
            case 'i':
                pkt_type = TYPE_INJECT;
                jmp++;
                break;
            case 'r':
                pkt_type = TYPE_REMOVE;
                jmp++;
                break;
            case 's':
                thrashd_host = optarg;
                jmp += 2;
                break;
            case 'p':
                jmp += 2;
                thrashd_port = atoi(optarg);
                break;
            case 'h':
                printf("Usage %s [opts] <addr1> <addr2> ...\n%s",
                       argv[0], help);
                exit(1);
        } /* switch */
    }

    return(jmp);
}

void
resp_callback(thrash_client_t * cli, thrash_resp_t * resp)
{

    event_base_loopbreak(cli->evbase);
    printf("Done!\n");
}

int
main(int argc, char **argv)
{
    int                ret,
                       i;
    struct event_base *base;
    thrash_client_t   *lc;

    globals_init();
    ret = parse_args(argc, argv);

    argv += ret;
    argc -= ret;

    if (!argc) {
        printf("%s\n", help);
        exit(1);
    }

    base = event_init();
    lc = init_thrash_client();
    lc->evbase = base;
    lc->resp_cb = resp_callback;
    lc->port = thrashd_port;
    thrash_client_sethost(lc, thrashd_host);
    thrash_client_settype(lc, pkt_type);
    thrash_client_connect(lc);

    for (i = 0; i < argc; i++) {
        printf("%s\n", argv[i]);
        thrash_client_lookup(lc, inet_addr(argv[i]), NULL);
        event_base_loop(base, 0);
    }

    return(0);
}
