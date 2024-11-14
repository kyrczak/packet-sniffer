#include "display.h"

void process_packet(sniffer_stats* stats, FILE* output_stream, unsigned char* buffor, int size) {
    struct iphdr* ip_header = (struct iphdr*)buffor;
    ++(stats->total);

    switch(ip_header->protocol) {
        case 6:
            ++(stats->tcp);
			tcp_packet_info(output_stream, buffor, size);
            break;
        case 17:
            ++(stats->udp);
            udp_packet_info(output_stream, buffor, size);
            break;
        default:
            break;
    }
    fprintf(output_stream, "Total: %d, TCP: %d, UDP: %d, OTHER: %d \n\n\n", stats->total, stats->tcp, stats->udp, stats->others);
}

void ip_packet_info(FILE* output_stream, unsigned char* buffer, int size) {
    struct sockaddr_in source, dest;
    struct iphdr* ip_header = (struct iphdr*)buffer;
    
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = ip_header->saddr;
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = ip_header->daddr;

    fprintf(output_stream, "\t IP HEADER\n");

    fprintf(output_stream, "Source IP: %s\n", inet_ntoa(source.sin_addr));
    fprintf(output_stream, "Destination IP: %s\n", inet_ntoa(dest.sin_addr));
    fprintf(output_stream, "Version: %d\n", ip_header->version);
    fprintf(output_stream, "Header length: %d\n", ip_header->ihl);
    fprintf(output_stream, "Type of service: %d\n", ip_header->tos);
    fprintf(output_stream, "Total length: %d\n", ntohs(ip_header->tot_len));
    fprintf(output_stream, "Identification: %d\n", ntohs(ip_header->id));
    fprintf(output_stream, "Fragment offset: %d\n", ntohs(ip_header->frag_off));
    fprintf(output_stream, "Time to live: %d\n", ip_header->ttl);
    fprintf(output_stream, "Protocol: %d\n", ip_header->protocol);
}

void udp_packet_info(FILE* output_stream, unsigned char* buffer, int size) {
    struct iphdr* ip_header = (struct iphdr*)buffer;
    unsigned short ip_header_length;
    ip_header_length = ip_header->ihl*4;
    struct udphdr* udp_header = (struct udphdr*)(buffer + ip_header_length);

    ip_packet_info(output_stream, buffer, size);

    fprintf(output_stream, "\t UDP HEADER\n");

    fprintf(output_stream, "Source port: %d\n", ntohs(udp_header->source));
    fprintf(output_stream, "Destination port: %d\n", ntohs(udp_header->dest));
    fprintf(output_stream, "Length: %d\n", ntohs(udp_header->len));
    fprintf(output_stream, "Checksum: %d\n", ntohs(udp_header->check));

    fprintf(output_stream, "IP HEADER \n");
    print_data(output_stream, buffer, ip_header_length);

    fprintf(output_stream, "UDP HEADER \n");
    print_data(output_stream, buffer + ip_header_length, sizeof(struct udphdr));

    fprintf(output_stream, "DATA \n");
    print_data(output_stream, buffer + ip_header_length + sizeof(struct udphdr), size - sizeof(struct udphdr) - ip_header_length);   
}

void tcp_packet_info(FILE* output_stream, unsigned char* buffer, int size) {
    unsigned short ip_header_length;
    struct iphdr* ip_header = (struct iphdr*)buffer;
    ip_header_length = ip_header->ihl*4;
    struct tcphdr* tcp_header = (struct tcphdr*)(buffer + ip_header_length);

    ip_packet_info(output_stream, buffer, size);

    fprintf(output_stream, "\t TCP HEADER\n");

    fprintf(output_stream, "Source port: %d\n", ntohs(tcp_header->th_sport));
    fprintf(output_stream, "Destination port: %d\n", ntohs(tcp_header->th_dport));
    fprintf(output_stream, "Sequence number: %d\n", ntohs(tcp_header->th_seq));
    fprintf(output_stream, "Ack number: %d\n", ntohs(tcp_header->th_ack));
    fprintf(output_stream, "Data offset: %d\n", tcp_header->doff);
    fprintf(output_stream, "Window size: %d\n", ntohs(tcp_header->th_win));
    fprintf(output_stream, "Checksum: %d\n", ntohs(tcp_header->th_sum));
    fprintf(output_stream, "Urgent pointer: %d\n", ntohs(tcp_header->th_urp));
    fprintf(output_stream, "FLAGS: \n");
    fprintf(output_stream, "\t URG:%d\n", tcp_header->urg);
    fprintf(output_stream, "\t ACK:%d\n", tcp_header->ack);
    fprintf(output_stream, "\t PSH:%d\n", tcp_header->psh);
    fprintf(output_stream, "\t RST:%d\n", tcp_header->rst);
    fprintf(output_stream, "\t SYN:%d\n", tcp_header->syn);
    fprintf(output_stream, "\t FIN:%d\n", tcp_header->fin);

    fprintf(output_stream, "IP HEADER \n");
    print_data(output_stream, buffer, ip_header_length);

    fprintf(output_stream, "TCP HEADER \n");
    print_data(output_stream, buffer + ip_header_length, tcp_header->doff*4);

    fprintf(output_stream, "DATA \n");
    print_data(output_stream, buffer + ip_header_length + tcp_header->doff*4, size - tcp_header->doff*4 - ip_header_length);
}

void print_data(FILE* output_stream, unsigned char* buffer, int size) {
    for(int i = 0; i < size; i++) {
        if(i != 0 && i % 16 == 0) {
            fprintf(output_stream, "\t");
            for(int j = i - 16; j < i; j++) {
                if(buffer[j] >= 32 && buffer[j] <= 128) {
                    fprintf(output_stream, "%c", (unsigned char)buffer[j]);
                } else {
                    fprintf(output_stream, ".");
                }
            }
            fprintf(output_stream, "\n");
        }
        if(i % 16 == 0) {
            fprintf(output_stream, "\t");
        }
        fprintf(output_stream, " %02x", (unsigned int)buffer[i]);
        if(i == size - 1) {
            for(int j = 0; j < 15 - i % 16; j++) {
                fprintf(output_stream, "   ");
            }
            fprintf(output_stream, "\t");
            for(int j = i - i % 16; j <= i; j++) {
                if(buffer[j] >= 32 && buffer[j] <= 128) {
                    fprintf(output_stream, "%c", (unsigned char)buffer[j]);
                } else {
                    fprintf(output_stream, ".");
                }
            }
            fprintf(output_stream, "\n");
        }
    }
}