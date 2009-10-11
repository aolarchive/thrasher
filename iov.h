#ifndef _IOV_H 
#define _IOV_H
typedef struct iov {
    char *buf;
    size_t to_read;
    size_t offset;
} iov_t;

void initialize_iov(iov_t *, size_t);
void reset_iov(iov_t * iovec);
int read_iov(iov_t * iovec, int sock);
int write_iov(iov_t * iovec, int sock);

#endif
