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

enum STREAM_TYPE {
    OUTPUT_FILE,
    OUTPUT_STREAM
};

void process_packet(sniffer_stats* stats, FILE* stream, unsigned char* buffer, int size);
void ip_packet_info(FILE* stream, unsigned char* buffer, int size);
void udp_packet_info(FILE* stream, unsigned char* buffer, int size);
void tcp_packet_info(FILE* stream, unsigned char* buffer, int size);
void print_data(FILE* stream, unsigned char* buffer, int size);

#endif