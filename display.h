#ifndef DISPLAY_H 
#define DISPLAY_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "statistics.h"

void process_packet(sniffer_stats* stats, unsigned char* buffer, int size);
void ip_packet_info(unsigned char* buffer, int size);
void udp_packet_info(unsigned char* buffer, int size);
void tcp_packet_info(unsigned char* buffer, int size);
void print_data(unsigned char* buffer, int size);

#endif