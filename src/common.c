#include "common.h"


void check_root_user(void) {
    if(geteuid() != 0) {
        printf("\nYou need to be root to run this.\n\n");
        exit(0);
    }
}


unsigned int host_convert(char *hostname) {
    static struct in_addr i;
    struct hostent *h;
    i.s_addr = inet_addr(hostname);
    if(i.s_addr == -1)
    {
        h = gethostbyname(hostname);
        if(h == NULL)
        {
            fprintf(stderr, "cannot resolve %s\n", hostname);
            exit(0);
        }
        memcpy(h->h_name, (char *)&i.s_addr, (unsigned long) h->h_length);
    }
    return i.s_addr;
}


uint16_t calc_ip_checksum(struct ip *ip_header) {
    uint32_t sum = 0;
    uint16_t *ptr = (uint16_t *)ip_header;
    int count = ip_header->ip_hl * 4;

    ip_header->ip_sum = 0;

    while (count > 1) {
        sum += *ptr++;
        count -= 2;
    }

    if (count > 0) {
        sum += *(uint8_t *)ptr;
    }

    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return (uint16_t)~sum;
}



uint16_t calc_udp_checksum(char* packet, size_t total_len) {
    uint32_t sum = 0;

    while (total_len > 1) {
        sum += *packet++;
        total_len -= 2;
    }

    if (total_len > 0) {
        sum += *(uint8_t *)packet;
    }

    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return (uint16_t)~sum;
}

