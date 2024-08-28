#include "display.h"

void process_packet(sniffer_stats* stats, unsigned char* buffor, int size) {
    struct iphdr* ip_header = (struct iphdr*)buffor;
    ++(stats->total);

    switch(ip_header->protocol) {
        case 6:
            ++(stats->tcp);
			tcp_packet_info(buffor, size);
            break;
        case 17:
            printf("UDP\n");
            break;
        default:
            break;
    }
    printf("Total: %d, TCP: %d, UDP: %d, OTHER: %d", stats->total, stats->tcp, stats->udp, stats->others);
}

void ip_packet_info(unsigned char* buffer, int size) {
    struct sockaddr_in source, dest;
    struct iphdr* ip_header = (struct iphdr*)buffer;
    
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = ip_header->saddr;
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = ip_header->daddr;

    printf("\t IP HEADER\n");

    printf("Source IP: %s\n", inet_ntoa(source.sin_addr));
    printf("Destination IP: %s\n", inet_ntoa(dest.sin_addr));
    printf("Version: %d\n", ip_header->version);
    printf("Header length: %d\n", ip_header->ihl);
    printf("Type of service: %d\n", ip_header->tos);
    printf("Total length: %d\n", ntohs(ip_header->tot_len));
    printf("Identification: %d\n", ntohs(ip_header->id));
    printf("Fragment offset: %d\n", ntohs(ip_header->frag_off));
    printf("Time to live: %d\n", ip_header->ttl);
    printf("Protocol: %d\n", ip_header->protocol);
}

void tcp_packet_info(unsigned char* buffer, int size) {
    unsigned short ip_header_length;
    struct iphdr* ip_header = (struct iphdr*)buffer;
    ip_header_length = ip_header->ihl*4;
    struct tcphdr* tcp_header = (struct tcphdr*)(buffer + ip_header_length);

    ip_packet_info(buffer, size);

    printf("\t TCP HEADER\n");

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

    printf("IP HEADER \n");
    print_data(buffer, ip_header_length);

    printf("TCP HEADER \n");
    print_data(buffer + ip_header_length, tcp_header->doff*4);

    printf("DATA \n");
    print_data(buffer + ip_header_length + tcp_header->doff*4, size - tcp_header->doff*4 - ip_header_length);
}

void print_data(unsigned char* buffer, int size) {
    for(int i = 0; i < size; i++) {
        if(i != 0 && i % 16 == 0) {
            printf("\t");
            for(int j = i - 16; j < i; j++) {
                if(buffer[j] >= 32 && buffer[j] <= 128) {
                    printf("%c", (unsigned char)buffer[j]);
                } else {
                    printf(".");
                }
            }
            printf("\n");
        }
        if(i % 16 == 0) {
            printf("\t");
        }
        printf(" %02x", (unsigned int)buffer[i]);
        if(i == size - 1) {
            for(int j = 0; j < 15 - i % 16; j++) {
                printf("   ");
            }
            printf("\t");
            for(int j = i - i % 16; j <= i; j++) {
                if(buffer[j] >= 32 && buffer[j] <= 128) {
                    printf("%c", (unsigned char)buffer[j]);
                } else {
                    printf(".");
                }
            }
            printf("\n");
        }
    }
}