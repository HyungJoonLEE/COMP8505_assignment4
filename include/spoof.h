#ifndef COMP_8505_ASSIGNMENT4_SNIFFER_H
#define COMP_8505_ASSIGNMENT4_SNIFFER_H

#include "common.h"

#define DEFAULT_COUNT 100
#define SIZE_ETHERNET 14


// tcpdump header (ether.h) defines ETHER_HDRLEN)
#ifndef ETHER_HDRLEN
#define ETHER_HDRLEN 14
#endif

#define NETSTAT "netstat -rn"
#define FLUSH_CASH1 "systemd-resolve --flush-caches"
#define FLUSH_CASH2 "resolvectl flush-caches"
#define FILTER "udp dst port 53"
#define FORWARD_1 "echo 1 > /proc/sys/net/ipv4/ip_forward"
#define FORWARD_0 "echo 0 > /proc/sys/net/ipv4/ip_forward"
#define IPT_UDP "iptables -A INPUT -p udp --sport 53 -j DROP"
#define IPT_TCP "iptables -A INPUT -p tcp --sport 53 -j DROP"
#define IPT_FLUSH "iptables -F"


struct options_spoofing {
    unsigned int count;
    char target_ip[16];
    unsigned char target_MAC[6];
    char spoofing_ip[16];
    char const_spoofing_ip[16];
    char request_url[64];
    char device_ip[16];
    char device_ipv6[40];
    unsigned char device_MAC[6];
    char gateway_ip[16];
    char dns_ip[16];
    uint8_t* query_name;
    uint8_t type[2];
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
void print_input(void);
void set_iptables_rule(void);
void options_spoofing_init(struct options_spoofing *option);
void program_setup(int argc, char *argv[]);
void get_MAC_address(void);
void get_ip_address(void);
void get_url_address(void);
void get_device_ip(char* nic_device);
void get_gateway_ip_address(void);
void get_target_ip_address(void);
void get_target_MAC_address(void);
bool is_valid_ipaddress(char *ip_address);
void sig_handler(int signum);
unsigned short create_dns_answer(char* answer, unsigned short* size_answer);
unsigned short create_dns_header(u_char* dns, struct dnshdr* dh);
unsigned short create_udp_header(u_char* udp, struct udphdr* uh, unsigned short size);
unsigned short create_ip_header(u_char* ip, struct iphdr* ih, unsigned short size);
unsigned short create_ethernet_header(u_char* ether, struct ether_header* eh);
void* arp_poisoning();
void process_ipv4(const struct pcap_pkthdr* pkthdr, const u_char* packet);
void handle_DNS_query(u_char * dns_query, char *request);
void send_dns_answer(char* response_packet, uint16_t size_response_payload);
void pkt_callback(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet);

#endif COMP_8505_ASSIGNMENT4_SNIFFER_H
