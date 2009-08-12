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
static unsigned int test_number = 0;
static char    *thrashd_addr = "127.0.0.1";
static int      thrashd_port = 1972;
static char    *inject_addr = NULL;
static int      sleeper = 0;

void
parse_args(int argc, char **argv)
{
    int             c;

    while ((c = getopt(argc, argv, "hirs:p:a:t:u:")) != -1) {
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
	case 't':
	    mode = 0;
	    test_number = atoi(optarg);
	    break;
	case 'u':
	    sleeper = atoi(optarg);
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
thrashd_thrasher(void)
{
    struct sockaddr_in inaddr;
    uint32_t addr;
    int sock;
    
    addr = inet_addr(thrashd_addr);
    inaddr.sin_family = AF_INET;
    inaddr.sin_addr.s_addr = addr;
    inaddr.sin_port = htons(thrashd_port);
    sock = socket(PF_INET, SOCK_STREAM, 0);
    connect(sock, (struct sockaddr *)&inaddr, sizeof(inaddr));

    
    uint32_t start = 1;
    uint32_t end   = test_number;
    uint32_t i;
   for (i = start; i < end; i++)
   {
       uint8_t type = 0;
       uint32_t src_ip = i;
       uint16_t uri_len = htons(2);
       uint16_t host_len = htons(2);
       uint8_t  ret;
       struct iovec vec[6];

       vec[0].iov_base = &type;
       vec[0].iov_len = 1; 
       vec[1].iov_base = &src_ip;
       vec[1].iov_len = sizeof(uint32_t);
       vec[2].iov_base = &uri_len;
       vec[2].iov_len = sizeof(uint16_t);
       vec[3].iov_base = &host_len;
       vec[3].iov_len = sizeof(uint16_t);
       vec[4].iov_base = "##"; 
       vec[4].iov_len = 2; 
       vec[5].iov_base = "##"; 
       vec[5].iov_len = 2; 

       writev(sock, vec, 6);
       recv(sock, &ret, 1, 0);

       if (i % 1000 == 0)
	   printf("%d\n", i);

   }

   close(sock);
}
    
void
thrashd_injector(uint32_t inject_addr)
{
    int             sock;
    uint32_t addr;
    struct sockaddr_in inaddr;
    struct iovec    vec[4];

    if ((addr = inet_addr(thrashd_addr)) < 0) {
        fprintf(stderr, "%s is not a valid thrashd addr\n", thrashd_addr);
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
    vec[1].iov_base = &inject_addr;
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

    if (test_number)
	thrashd_thrasher();
    else
	thrashd_injector(inet_addr(inject_addr));

    return 0;
}
