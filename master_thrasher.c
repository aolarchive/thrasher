#include <stdint.h>
#include <errno.h>
#include <sys/socket.h>
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


/*
 * inject or remove 
 */
static uint8_t  mode = 2;
static char    *thrashd_addr = "127.0.0.1";
static int      thrashd_port = 1972;
static char    *inject_addr = NULL;

void
parse_args(int argc, char **argv)
{
    int             c;

    while ((c = getopt(argc, argv, "hirs:p:a:")) != -1) {
        switch (c) {
        case 'i':
            mode = 2;
            break;
        case 'r':
            mode = 1;
            break;
        case 's':
            thrashd_addr = optarg;
            break;
        case 'p':
            thrashd_port = atoi(optarg);
            break;
        case 'a':
            inject_addr = optarg;
            break;
        case 'h':
            printf("Usage: %s [opts]\n", argv[0]);
            printf(" -i: set mode to injection\n"
                   " -r: set mode to remove\n"
                   " -s <thrashd addr>\n"
                   " -p <thrashd port>\n"
                   " -a <address to inject/remove\n");
            exit(1);
        }
    }
}

void
beef_injector(void)
{
    int             sock;
    uint32_t        to_inject,
                    addr;
    struct sockaddr_in inaddr;
    struct iovec    vec[2];

    if ((addr = inet_addr(thrashd_addr)) < 0) {
        fprintf(stderr, "%s is not a valid thrashd addr\n", thrashd_addr);
        exit(1);
    }

    if ((to_inject = inet_addr(inject_addr)) < 0) {
        fprintf(stderr, "%s is not a valid inject/remove addr\n",
                inject_addr);
        exit(1);
    }

    inaddr.sin_family = AF_INET;
    inaddr.sin_addr.s_addr = addr;
    inaddr.sin_port = htons(thrashd_port);

    if ((sock = socket(PF_INET, SOCK_STREAM, 0)) <= 0) {
        fprintf(stderr, "Error opening socket: %s\n", strerror(errno));
        exit(1);
    }

    if (connect(sock, (struct sockaddr *) &inaddr, sizeof(inaddr)) < 0) {
        fprintf(stderr, "Error connecting to host: %s\n", strerror(errno));
        exit(1);
    }

    vec[0].iov_base = &mode;
    vec[0].iov_len = sizeof(uint8_t);
    vec[1].iov_base = &to_inject;
    vec[1].iov_len = sizeof(uint32_t);

    writev(sock, vec, 2);
    close(sock);
}

int
main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "try -h, buddy\n");
        exit(1);
    }
    parse_args(argc, argv);
    beef_injector();
    return 0;
}
