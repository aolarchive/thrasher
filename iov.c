/******************************************************************************/
/* iov.c  -- utilities for io vectors
 *
 * Copyright 2007-2013 AOL Inc. All rights reserved.
 *
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include "iov.h"


void
initialize_iov(iov_t * iovec, size_t len)
{
    if (!iovec) {
        fprintf(stderr, "iovec is not initialized");
        exit(1);
    }

    if (iovec->buf)
        free(iovec->buf);

    if (!(iovec->buf = malloc(len))) {
        fprintf(stderr, "Out of memory: %s", strerror(errno));
        exit(1);
    }

    iovec->to_read = len;
    iovec->offset = 0;
}

void
reset_iov(iov_t * iovec)
{
    if (iovec->buf)
        free(iovec->buf);

    iovec->buf = NULL;
    iovec->to_read = 0;
    iovec->offset = 0;
}

int
read_iov(iov_t * iovec, int sock)
{
    int             bytes_read;

    bytes_read = recv(sock, &iovec->buf[iovec->offset], iovec->to_read,
                      MSG_NOSIGNAL);

    if (bytes_read <= 0)
        return -1;

    iovec->offset += bytes_read;
    iovec->to_read -= bytes_read;

    return iovec->to_read;
}

int
write_iov(iov_t * iovec, int sock)
{
    int             bytes_written;

    bytes_written = send(sock,
                         &iovec->buf[iovec->offset], iovec->to_read,
                         MSG_NOSIGNAL);

    if (bytes_written <= 0)
        return -1;

    iovec->offset += bytes_written;
    iovec->to_read -= bytes_written;

    return iovec->to_read;
}
