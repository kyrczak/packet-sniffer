#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>


void process_packet(unsigned char* buffer, int size);
void ip_packet_info(unsigned char* buffer, int size);
void tcp_packet_info(unsigned char* buffer, int size);

int total, tcp, udp, icmp, others, igmp, arp, rarp, ip, main_socket;

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

void ip_packet_info(unsigned char* buffer, int size) {
    struct iphdr* ip_header = (struct iphdr*)buffer;
    struct sockaddr_in source, dest;

    source.sin_addr.s_addr = ip_header->saddr;
    dest.sin_addr.s_addr = ip_header->daddr;

    printf("Source IP: %s\n", inet_ntoa(source.sin_addr));
    printf("Destination IP: %s\n", inet_ntoa(dest.sin_addr));
}

void tcp_packet_info(unsigned char* buffer, int size) {
    struct iphdr* ip_header = (struct iphdr*)buffer;
    struct tcphdr* tcp_header = (struct tcphdr*)(buffer + ip_header->ihl*4);

    printf("Source port: %d\n", ntohs(tcp_header->th_sport));
    printf("Destination port: %d\n", ntohs(tcp_header->th_dport));
}