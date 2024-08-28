#ifndef STATISTICS_H
#define STATISTICS_H

typedef struct statistics {
    unsigned int total;
    unsigned int tcp;
    unsigned int udp;
    unsigned int icmp;
    unsigned int others;
    unsigned int igmp;
    unsigned int arp;
    unsigned int rarp;
    unsigned int ip;
} sniffer_stats;

#endif