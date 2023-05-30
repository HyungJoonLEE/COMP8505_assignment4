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

    if (ip->ip_p == IPPROTO_UDP) handle_UDP(args, pkthdr, packet);
}


void handle_UDP (u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    const struct sniff_udp *udp = 0;
    const struct my_ip *ip;              	// The IP header
    const char *payload;

    int size_ip;
    int size_udp;
    int size_payload;

//    printf ("[ UDP Header ]\n");

    ip = (struct my_ip*) (packet + SIZE_ETHERNET);
    size_ip = IP_HL (ip) * 4;


    // define/compute udp header offset
    udp = (struct sniff_udp*) (packet + SIZE_ETHERNET + size_ip);
    size_udp = 8;


    printf ("[ UDP Header ]\n");
    printf("    Src port: %d\n", ntohs(udp->uh_sport));
    opts.device_port = ntohs(udp->uh_sport);
    send_dns.udp.uh_dport = htons(opts.device_port);
    printf("    Dst port: %d\n", ntohs(udp->uh_dport));


    // define/compute tcp payload (segment) offset
    payload = (u_char *) (packet + SIZE_ETHERNET + size_ip + size_udp);

    // compute tcp payload (segment) size
    size_payload = ntohs(ip->ip_len) - (size_ip + size_udp);


    // Print payload data, including binary translation
    if (size_payload > 0) {
        opts.device_port = ntohs(udp->uh_sport);
        send_dns.udp.uh_dport = htons( opts.device_port);
        printf("Payload (%d bytes):\n", size_payload);
        print_payload(payload, size_payload);
    }
}
