#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h> // Add this line to include the tcp header file
#include <netinet/udp.h>
#include <arpa/inet.h>


void process_packet(unsigned char* buffer, int size);

int total, main_socket;

int main() {
    main_socket = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if(main_socket < 0) {
        perror("socket");
        return 1;
    }
    printf("Socket created successfully\n");

    unsigned char* buffer = (unsigned char*)malloc(65536);
    
    while(1) {
        int recv_bytes = recv(main_socket, buffer, sizeof(buffer), 0);
        if(recv_bytes < 0) {
            perror("recv error, failed to get packets\n");
            return 1;
        }

        process_packet(buffer, recv_bytes);

    }
    return 0;
}


void process_packet(unsigned char* buffor, int size) {
    struct iphdr* ip_header = (struct iphdr*)buffor;
    ++total;

    switch(ip_header->protocol) {
        case 6:
            printf("TCP\n");
            break;
        case 17:
            printf("UDP\n");
            break;
        default:
            printf("Other\n");
            break;
    }

}

void tcp_packet_info(unsigned char* buffer, int size) {
    struct iphdr* ip_header = (struct iphdr*)buffer;
    struct tcphdr* tcp_header = (struct tcphdr*)(buffer + ip_header->ihl*4);

    //Print IP info

    printf("Source port: %d\n", ntohs(tcp_header->source));
    printf("Destination port: %d\n", ntohs(tcp_header->dest));
}