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
    char gateway_ip[16];
    uint16_t device_port;
    bool ip_flag;
    char buffer[65507];
};


struct etherhdr{
    u_char ether_dhost[ETHER_ADDR_LEN]; /* dst address */
    u_char ether_shost[ETHER_ADDR_LEN]; /* src address */
    u_short ether_type; /* network protocol */
};


struct my_ip {
    u_int8_t	ip_vhl;		/* header length, version */
#define IP_V(ip)	(((ip)->ip_vhl & 0xf0) >> 4)
#define IP_HL(ip)	((ip)->ip_vhl & 0x0f)
    u_int8_t	ip_tos;		/* type of service */
    u_int16_t	ip_len;		/* total length */
    u_int16_t	ip_id;		/* identification */
    u_int16_t	ip_off;		/* fragment offset field */
#define	IP_DF 0x4000			/* dont fragment flag */
#define	IP_MF 0x2000			/* more fragments flag */
#define	IP_OFFMASK 0x1fff		/* mask for fragmenting bits */
    u_int8_t	ip_ttl;		/* time to live */
    u_int8_t	ip_p;		/* protocol */
    u_int16_t	ip_sum;		/* checksum */
    struct	in_addr ip_src, ip_dst;	/* source and dest address */
};


struct sniff_udp {
    u_int16_t uh_sport;                /* source port */
    u_int16_t uh_dport;                /* destination port */
    u_int16_t uh_ulen;                 /* udp length */
    u_int16_t uh_sum;                  /* udp checksum */
};


/* DNS header */
struct dnshdr {
    char id[2];
    char flags[2];
    char qdcount[2];
    char ancount[2];
    char nscount[2];
    char arcount[2];
};

/* DNS query structure */
struct dnsquery {
    char *qname;
    char qtype[2];
    char qclass[2];
};

/* DNS answer structure */
struct dnsanswer {
    char *name;
    char atype[2];
    char aclass[2];
    char ttl[4];
    char RdataLen[2];
    char *Rdata;
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
void create_header(char* response_packet, uint16_t size_response_payload);

u_int16_t handle_ethernet (u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet);
void handle_IP (u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet);
void handle_UDP (u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet);
void handle_DNS(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet, struct dnshdr **dns_hdr, struct dnsquery *dns_query);
void handle_DNS_request(struct dnsquery *dns_query, char *request);
uint16_t set_payload(struct dnshdr *dns_hdr, char* payload_size);
void send_dns_answer(char* response_packet, uint16_t size_response_payload);

void print_payload (const u_char *, int);
void print_hex_ascii_line (const u_char *, int, int);
void pkt_callback(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet);

#endif COMP_8505_ASSIGNMENT4_SNIFFER_H
