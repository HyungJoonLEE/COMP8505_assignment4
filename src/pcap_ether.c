/*---------------------------------------------------------------------------------------------
--	SOURCE FILE:	proc_ether.c -   Process Ethernet packets
--
--	FUNCTIONS:		libpcap - packet filtering library based on the BSD packet
--					filter (BPF)
--
--	DATE:			May 15, 2023
--				    Added personal function for assignment
--
--	REVISIONS:		(Date and nic_description)
--
--	DESIGNERS:		Based on the code by Martin Casado, Aman Abdulla
--					Also code was taken from tcpdump source, namely the following files..
--					print-ether.c
--					print-ip.c
--					ip.h
--					Modified & redesigned: Aman Abdulla: April 23, 2006
--
--	STUDENT:		HyungJoon LEE
-------------------------------------------------------------------------------------------------*/

#include "spoof.h"

u_int16_t handle_ethernet (u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    u_int caplen = pkthdr->caplen;
    u_int length = pkthdr->len;
    struct ether_header *eptr;  /* net/ethernet.h */
    u_short ether_type;

    if (caplen < ETHER_HDRLEN) {
        fprintf(stdout,"Packet length less than ethernet header length\n");
        return -1;
    }

    // Start with the Ethernet header
    eptr = (struct ether_header *) packet;
    ether_type = ntohs(eptr->ether_type);

//    // IPv4 packet
//    if (ether_type == ETHERTYPE_IP) {
//        printf("[ IPv4 Header ]\n");
//    }
//    // IPv6 packet
//    else if (ether_type == ETHERTYPE_IPV6) {
//        printf("[ IPV6 Header ]\n");
//    }
//    // ARP packet
//    else if (ether_type == ETHERTYPE_ARP) {
//        printf("[ ARP Header ]\n");
//    }
//    else printf("[ Unknown ]\n");
//
//    printf("    Total length: %d\n", length);

    return ether_type;
}
