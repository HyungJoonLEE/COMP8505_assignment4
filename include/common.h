#ifndef COMP_8505_ASSIGNMENT4__COMMON_H
#define COMP_8505_ASSIGNMENT4__COMMON_H


#include <stdio.h>
#include <sys/prctl.h>
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <ctype.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <stddef.h>
#include <limits.h>
#include <sys/types.h>
#include <getopt.h>
#include <regex.h>
#include <inttypes.h>
#include <pcap/bpf.h>
#include <pcap/pcap.h>
#include <pcap.h>
#include <stdlib.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/wait.h>
#include <pthread.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <setjmp.h>
#include "extern.h"


#define DEFAULT_PORT 53000
#define TRUE 1
#define FALSE 0
#define MASK "bash_ass4"


void check_root_user(void);
unsigned int host_convert(char *hostname);
uint16_t calc_ip_checksum(struct ip *ip_header);
uint16_t calc_udp_checksum(struct udphdr *udp_header);



#endif COMP_8505_ASSIGNMENT4_COMMON_H
