#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>


void process_packet(unsigned char* buffer, int size);
void ip_packet_info(unsigned char* buffer, int size);
void tcp_packet_info(unsigned char* buffer, int size);

int total, tcp, udp, icmp, others, igmp, arp, rarp, ip, main_socket, saddr_size;

int main() {
    main_socket = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if(main_socket < 0) {
        perror("socket");
        return 1;
    }
    printf("Socket created successfully\n");

    unsigned char* buffer = (unsigned char*)malloc(65536);
    struct sockaddr saddr;
    struct in_addr in;
    
    while(1) {
        saddr_size = sizeof saddr;
        int recv_bytes = recvfrom(main_socket, buffer , 65536 , 0 , &saddr , &saddr_size);
        if(recv_bytes < 0) {
            perror("recv error, failed to get packets\n");
            return 1;
        }
		printf("Received %d bytes\n", recv_bytes);
        process_packet(buffer, recv_bytes);

    }

    close(main_socket);
    printf("Socket closed\n");
    return 0;
}


void process_packet(unsigned char* buffor, int size) {
    struct iphdr* ip_header = (struct iphdr*)buffor;
    ++total;

    switch(ip_header->protocol) {
        case 6:
            ++tcp;
            printf("TCP\n");
			tcp_packet_info(buffor, size);
            break;
        case 17:
            printf("UDP\n");
            break;
        default:
            break;
    }
    printf("Total: %d, TCP: %d, UDP: %d, OTHER: %d", total, tcp, udp, others);
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
    printf("Sequence number: %d\n", ntohs(tcp_header->th_seq));
    printf("Ack number: %d\n", ntohs(tcp_header->th_ack));
    printf("Data offset: %d\n", tcp_header->doff);
    printf("Window size: %d\n", ntohs(tcp_header->th_win));
    printf("Checksum: %d\n", ntohs(tcp_header->th_sum));
    printf("Urgent pointer: %d\n", ntohs(tcp_header->th_urp));
    printf("FLAGS: \n");
    printf("\t URG:%d\n", tcp_header->urg);
    printf("\t ACK:%d\n", tcp_header->ack);
    printf("\t PSH:%d\n", tcp_header->psh);
    printf("\t RST:%d\n", tcp_header->rst);
    printf("\t SYN:%d\n", tcp_header->syn);
    printf("\t FIN:%d\n", tcp_header->fin);
}