#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "statistics.h"

void process_packet(sniffer_stats* stats, unsigned char* buffer, int size);
void ip_packet_info(unsigned char* buffer, int size);
void tcp_packet_info(unsigned char* buffer, int size);