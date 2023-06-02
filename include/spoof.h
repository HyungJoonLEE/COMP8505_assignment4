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
    char device_ipv6[40];
    char dns_ip[16];
    char dns_ipv6[40];
    uint16_t device_port;

    bool ipv6_flag;
    uint16_t ip_id;
    unsigned short tid;
    uint8_t* query_name;
    uint8_t type[2];
};


struct etherhdr{
    u_char ether_dhost[ETHER_ADDR_LEN]; /* dst address */
    u_char ether_shost[ETHER_ADDR_LEN]; /* src address */
    u_short ether_type; /* network protocol */
};


/* DNS query structure */
struct dnsquery {
    uint8_t* name;
    uint8_t type[2];
    uint8_t class[2];
};


/* DNS answer structure */
struct dnsanswer {
    uint8_t name[2];
    uint8_t type[2];
    uint16_t class;
    uint32_t ttl;
    uint16_t datalen;
    uint8_t address[4];
};


/* DNS header */
struct dnshdr {
    uint16_t id; // identification number

    uint8_t rd :1; // recursion desired
    uint8_t tc :1; // truncated message
    uint8_t aa :1; // authoritive answer
    uint8_t opcode :4; // purpose of message
    uint8_t qr :1; // query/response flag

    uint8_t rcode :4; // response code
    uint8_t cd :1; // checking disabled
    uint8_t ad :1; // authenticated data
    uint8_t z :1; // its z! reserved
    uint8_t ra :1; // recursion available

    uint16_t q_count; // number of question entries
    uint16_t ans_count; // number of answer entries
    uint16_t auth_count; // number of authority entries
    uint16_t add_count; // number of resource entries
};







// Function Prototypes
void options_spoofing_init(struct options_spoofing *option);
void program_setup(int argc, char *argv[]);
void get_ip_address(void);
void get_url_address(void);
void get_device_ip(char* nic_device);
bool is_valid_ipaddress(char *ip_address);
void sig_handler(int signum);

void process_ipv4(const struct pcap_pkthdr* pkthdr, const u_char* packet);
void create_ipv4_header(char* response_packet, uint16_t size_dns_payload, uint16_t size_response_payload);

void process_ipv6(const struct pcap_pkthdr* pkthdr, const u_char* packet);
void create_ipv6_header(char* response_packet, uint16_t size_dns_payload, uint16_t size_response_payload);

void handle_DNS_query(struct dnsquery* dns_query, char *request);
uint16_t set_payload(struct dnshdr *dns_hdr, char* payload_size, char* request, bool flag);
void send_dns_answer(char* response_packet, uint16_t size_response_payload);
void send_dns_answer2(char* response_packet, uint16_t size_response_payload);

void pkt_callback(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet);

#endif COMP_8505_ASSIGNMENT4_SNIFFER_H
