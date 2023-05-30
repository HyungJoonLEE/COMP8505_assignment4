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
#include "extern.h"

// Check all the headers in the Ethernet frame
void pkt_callback(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    u_int16_t type = handle_ethernet(args, pkthdr, packet);

    /* handle the IP packet */
    if(type == ETHERTYPE_IP) handle_IP(args, pkthdr, packet);

    /* handle the ARP packet */
    else if (type == ETHERTYPE_ARP) {}

    /* handle reverse arp packet */
    else if (type == ETHERTYPE_REVARP){}
}


// This function will parse the IP header and print out selected fields of interest
void handle_IP (u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    const struct my_ip* ip;
    u_int length = pkthdr->len;
    u_int hlen, off, version;
    int len;

    ip = (struct my_ip*) (packet + sizeof(struct ether_header));
    length -= sizeof(struct ether_header);
    len     = ntohs(ip->ip_len);
    hlen    = IP_HL(ip);
    version = IP_V(ip);

    // make sure that the packet is of a valid length
    if (length < sizeof(struct my_ip)) {
        // printf("   Truncated IP %d", length);
        exit (1);
    }

    // verify version
    if(version != 4) {
        // printf("    Unknown version %d\n", version);
        exit (1);
    }

    // verify the header length */
    if(hlen < 5 ) {
        // printf("  Bad header length %d \n", hlen);
    }

    // Ensure that we have as much of the packet as we should
    if (length < (u_int)len) {
        // printf("\n  Truncated IP - %d bytes missing\n", (u_int) len - length);
    }

    // Ensure that the first fragment is present
    off = ntohs(ip->ip_off);
    if ((off & 0x1fff) == 0 ) {	// i.e, no 1's in first 13 bits
        printf("    Version: %d\n", version);
        printf("    Header Length: %d\n", hlen);
        printf("    Fragment Offset: %d\n", off);
        printf("    IP: %s -> ", inet_ntoa(ip->ip_src));
        printf("%s\n", inet_ntoa(ip->ip_dst));
    }

    switch (ip->ip_p) {
        case IPPROTO_TCP:
//            printf("    Protocol: TCP\n");
//            handle_TCP(args, pkthdr, packet);
            break;
        case IPPROTO_UDP:
            printf("    Protocol: UDP\n");
            handle_UDP(args, pkthdr, packet);
            break;
        case IPPROTO_ICMP:
//            printf("    Protocol: ICMP\n");
            break;
        case IPPROTO_IP:
//            printf("    Protocol: IP\n");
            break;
        default:
            printf("    Protocol: unknown\n");
            break;
    }
}


// This function will parse the IP header and print out selected fields of interest
void handle_TCP (u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
	const struct sniff_tcp *tcp = 0;          // The TCP header
	const struct my_ip *ip;              	// The IP header 
    const char *payload;                    // Packet payload

  	int size_ip;
    int size_tcp;
    int size_payload;


    printf ("[ TCP Header ]\n");

    ip = (struct my_ip*) (packet + SIZE_ETHERNET);
    size_ip = IP_HL (ip) * 4;

    // define/compute tcp header offset
    tcp = (struct sniff_tcp*) (packet + SIZE_ETHERNET + size_ip);
    size_tcp = TH_OFF(tcp) * 4;

    if (size_tcp < 20) {
        printf("   * Control Packet? length: %u bytes\n", size_tcp);
        exit(1);
    }

    printf("    Src port: %d\n", ntohs(tcp->th_sport));
    printf("    Dst port: %d\n", ntohs(tcp->th_dport));

    // define/compute tcp payload (segment) offset
    payload = (u_char *) (packet + SIZE_ETHERNET + size_ip + size_tcp);

    // compute tcp payload (segment) size
    size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);


    // Print payload data, including binary translation
    if (size_payload > 0) {
        printf("    Payload (%d bytes):\n", size_payload);
        print_payload(payload, size_payload);
    }
}


void handle_UDP (u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    const struct sniff_udp *udp = 0;
    const struct my_ip *ip;              	// The IP header
    const char *payload;

    int size_ip;
    int size_udp;
    int size_payload;

    printf ("[ UDP Header ]\n");

    ip = (struct my_ip*) (packet + SIZE_ETHERNET);
    size_ip = IP_HL (ip) * 4;


    // define/compute udp header offset
    udp = (struct sniff_udp*) (packet + SIZE_ETHERNET + size_ip);
    size_udp = 8;


    printf("    Src port: %d\n", ntohs(udp->uh_sport));
    printf("    Dst port: %d\n", ntohs(udp->uh_dport));


    // define/compute tcp payload (segment) offset
    payload = (u_char *) (packet + SIZE_ETHERNET + size_ip + size_udp);

    // compute tcp payload (segment) size
    size_payload = ntohs(ip->ip_len) - (size_ip + size_udp);


    // Print payload data, including binary translation
    if (size_payload > 0) {
        printf("    Payload (%d bytes):\n", size_payload);

        print_payload(payload, size_payload);
    }
}
