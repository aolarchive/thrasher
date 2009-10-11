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
#include <event.h>
#include "iov.h"
#include "thrasher.h"


thrash_clicfg_t *cli_cfg_init(void)
{
    return calloc(sizeof(thrash_clicfg_t), 1);
}

int main(int argc, char **argv)
{
    return 0;
}
