#ifndef COMP_8505_ASSIGNMENT4_SNIFFER_H
#define COMP_8505_ASSIGNMENT4_SNIFFER_H

#include "common.h"

#define DEFAULT_COUNT 100
#define SIZE_ETHERNET 14


// tcpdump header (ether.h) defines ETHER_HDRLEN)
#ifndef ETHER_HDRLEN
#define ETHER_HDRLEN 14
#endif

#define CMD "netstat -rn"
#define FLUSH_CASH "systemd-resolve --flush-caches"
#define FILTER "udp dst port 53"


struct options_spoofing {
    unsigned int count;
    char spoofing_ip[16];
    char request_url[16];
    char device_ip[16];
    char dns_ip[16];

    unsigned short ipid;
    uint16_t tid;
    uint16_t device_port;
};


struct etherhdr{
    u_char ether_dhost[ETHER_ADDR_LEN]; /* dst address */
    u_char ether_shost[ETHER_ADDR_LEN]; /* src address */
    u_short ether_type; /* network protocol */
};


/* DNS query structure */
struct dnsquery {
    char *name;
    uint16_t type;
    uint16_t class;
};


/* DNS answer structure */
struct dnsanswer {
    char *name;
    uint16_t type;
    uint16_t class;
    uint32_t ttl;
    uint16_t datalen;
    uint32_t address;
};


/* DNS header */
struct dnshdr {
    uint16_t id;
    uint16_t flags;
    uint16_t questions;
    uint16_t answer;
    uint16_t authority;
    uint16_t additional;
};







// Function Prototypes
void options_spoofing_init(struct options_spoofing *option);
void program_setup(int argc, char *argv[]);
void get_ip_address(void);
void get_url_address(void);
void find_gateway(void);
void get_device_ip(char* nic_device);
bool is_valid_ipaddress(char *ip_address);
void sig_handler(int signum);

void process_ipv4(const struct pcap_pkthdr* pkthdr, const u_char* packet);
void process_ipv6(const struct pcap_pkthdr* pkthdr, const u_char* packet);

void create_header(char* response_packet, uint16_t size_response_payload);

u_int16_t handle_ethernet (u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet);
void handle_IP (u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet);
void handle_UDP (u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet);
void handle_DNS(const struct pcap_pkthdr* pkthdr, const u_char* packet, struct dnshdr **dns_hdr, struct dnsquery *dns_query);
void handle_DNS_query(struct dnsquery* dns_query, char *request);
uint16_t set_payload(struct dnshdr *dns_hdr, char* payload_size, char* request);
void send_dns_answer(char* response_packet, uint16_t size_response_payload);

void print_payload (const u_char *, int);
void print_hex_ascii_line (const u_char *, int, int);
void pkt_callback(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet);

#endif COMP_8505_ASSIGNMENT4_SNIFFER_H
