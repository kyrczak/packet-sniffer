#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdbool.h>

#include "display.h"
#include "statistics.h"

#define PACKET_SIZE 65536
int main_socket, saddr_size;

int check_types(int argc, char* argv[]);

int main(int argc, char* argv[]) {

    if (argc < 2) {
        printf("Incorrect use of packet sniffer! \n Please launch program with argument --help to learn how to use packet sniffer. \n");
        return 1;
    }

    if (strcmp(argv[1],"--help") == 0) {
        printf("To launch sniffer you must specify which protocol to use. \n If you want to use TCP please input arguement -t TCP, in case you want to use UDP write -t UDP. \n");
        return 0;
    }

    if (check_types(argc, argv) == 0) {
        printf("Incorrect argument please use --help to learn more \n");
        return 1;
    }   

    if (strcmp(argv[2],"TCP") == 0) {
        main_socket = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    }
    else {
        main_socket = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    }

    sniffer_stats *statistics = calloc(1, sizeof(sniffer_stats));
    if(main_socket < 0) {
        perror("socket");
        return 1;
    }
    printf("Socket created successfully\n");

    unsigned char* buffer = (unsigned char*)malloc(PACKET_SIZE);
    struct sockaddr saddr;
    
    while(true) {
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

int check_types(int argc, char *argv[]) {
    if(strcmp(argv[1],"-t") != 0) {
        return 0;
    }
    if(((strcmp(argv[2],"UDP") == 0) || (strcmp(argv[2],"TCP") == 0)) && !((strcmp(argv[2],"UDP") == 0) && (strcmp(argv[2],"TCP") == 0))) {
        return 1;
    }
    else {
        return 0;
    }
}