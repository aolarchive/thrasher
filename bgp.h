#include <sys/un.h>
#include <arpa/inet.h>
#include "bgpd.h"

typedef struct _bgp_community {
    uint16_t asn;
    uint16_t community;
} bgp_community_t;

int thrash_bgp_connect(const char *);
int thrash_bgp_inject(const uint32_t, const bgp_community_t *, int);
