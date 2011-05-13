#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>

#include "iov.h"
#include "thrasher.h"

void
resp_callback(thrash_client_t * tclient, thrash_resp_t * tresp) {
    printf("%u is %s!\n", tclient->addr_lookup, tresp->permit ? "BLOCKED" : "NOT BLOCKED");

    event_base_loopbreak(tclient->evbase);
    free_thrash_resp(tresp);
}

int
main(int argc, char ** argv) {
    struct event_base * evbase  = NULL;
    thrash_client_t   * tclient = NULL;
    client_query_t    * tquery  = NULL;

    /* addr port ip */

    if (argc < 4) {
        fprintf(stderr, "Usage: %s <thrashd addr> <thrashd port> <ip>\n", argv[0]);
        return -1;
    }

    evbase           = event_init();
    tclient          = init_thrash_client();
    tquery           = create_v1_query("stupid.com", "/herp/derp");

    tclient->evbase  = evbase;
    tclient->resp_cb = resp_callback;
    tclient->port    = atoi(argv[2]);

    thrash_client_sethost(tclient, argv[1]);
    thrash_client_settype(tclient, TYPE_THRESHOLD_v1);
    thrash_client_connect(tclient);

    thrash_client_lookup(tclient, 0xFFFFFFFF, tquery);
    event_base_loop(evbase, 0);

    return 0;
}

