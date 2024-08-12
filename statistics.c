#include "statistics.h"

typedef struct sniffer_stats {
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