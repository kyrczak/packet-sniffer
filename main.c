#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "display.h"
#include "statistics.h"

#define PACKET_SIZE 65536

int main_socket, saddr_size;

int main(int argc, char* argv[]) {
    sniffer_stats *statistics = calloc(1, sizeof(sniffer_stats));
    main_socket = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if(main_socket < 0) {
        perror("socket");
        return 1;
    }
    printf("Socket created successfully\n");

    unsigned char* buffer = (unsigned char*)malloc(PACKET_SIZE);
    struct sockaddr saddr;
    
    while(1) {
        saddr_size = sizeof saddr;
        int recv_bytes = recvfrom(main_socket, buffer , PACKET_SIZE , 0 , &saddr , &saddr_size);
        if(recv_bytes < 0) {
            perror("recv error, failed to get packets\n");
            return 1;
        }
        process_packet(statistics, buffer, recv_bytes);

    }

    free(statistics);
    free(buffer);
    close(main_socket);
    printf("Socket closed\n");
    return 0;
}