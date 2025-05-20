#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include "packet_parser.h"

void init_packet_stats(packet_stats_t *stats) {
    if (stats == NULL) {
        fprintf(stderr, "Error: NULL pointer passed to init_packet_stats\n");
        return;
    }
    
    memset(stats, 0, sizeof(packet_stats_t));
    stats->start_time = time(NULL);
    stats->memory_usage = 0;
}

int get_packet_protocol(const u_char *packet, struct pcap_pkthdr *header) {
    if (packet == NULL || header == NULL) {
        return PROTO_OTHER;
    }
    
    // Parse Ethernet header
    struct eth_header *eth = (struct eth_header *)packet;
    
    // Check if it's an IP packet (Ethernet type 0x0800 is IP)
    if (ntohs(eth->ether_type) != ETHERTYPE_IP) {
        return PROTO_OTHER;
    }
    
    // Calculate the position of the IP header
    const u_char *ip_packet = packet + sizeof(struct eth_header);
    
    // Parse IP header
    struct ip_header *ip = (struct ip_header *)ip_packet;
    
    // Check IP header length to avoid buffer overruns
    int ip_header_len = IP_HL(ip) * 4;
    if (ip_header_len < 20) {
        // Invalid IP header length
        return PROTO_OTHER;
    }
    
    // Check if we have a complete IP packet
    if (sizeof(struct eth_header) + ntohs(ip->ip_len) > header->caplen) {
        // Incomplete packet
        return PROTO_OTHER;
    }
    
    // Determine protocol
    switch (ip->ip_p) {
        case IPPROTO_TCP:
            return PROTO_TCP;
        case IPPROTO_UDP:
            return PROTO_UDP;
        case IPPROTO_ICMP:
            return PROTO_ICMP;
        default:
            return PROTO_OTHER;
    }
}

void process_packet(const u_char *packet, struct pcap_pkthdr *header, packet_stats_t *stats) {
    if (packet == NULL || header == NULL || stats == NULL) {
        return;
    }
    
    // Determine the protocol type
    int protocol = get_packet_protocol(packet, header);
    
    // Update stats based on protocol
    switch (protocol) {
        case PROTO_TCP:
            stats->tcp_count++;
            break;
        case PROTO_UDP:
            stats->udp_count++;
            break;
        case PROTO_ICMP:
            stats->icmp_count++;
            break;
        case PROTO_OTHER:
            stats->other_count++;
            break;
    }
    
    stats->total_packets++;
    
    // Update memory usage approximation (size of the packet + overhead)
    stats->memory_usage += header->len + sizeof(struct pcap_pkthdr);
}

void print_stats(const packet_stats_t *stats) {
    if (stats == NULL) {
        return;
    }
    
    // Calculate percentages
    float tcp_percent = stats->total_packets > 0 ? 
                        (float)stats->tcp_count * 100 / stats->total_packets : 0;
    float udp_percent = stats->total_packets > 0 ? 
                        (float)stats->udp_count * 100 / stats->total_packets : 0;
    float icmp_percent = stats->total_packets > 0 ? 
                         (float)stats->icmp_count * 100 / stats->total_packets : 0;
    float other_percent = stats->total_packets > 0 ? 
                          (float)stats->other_count * 100 / stats->total_packets : 0;
    
    printf("\033[H\033[J");  // Clear screen
    printf("Packet Analyzer (E-VAS Tel Team)\n");
    printf("---------------------------------\n");
    printf("Current Statistics:\n");
    printf("[%ld seconds elapsed]\n", time(NULL) - stats->start_time);
    printf("Packets captured: %d\n", stats->total_packets);
    printf("TCP: %d (%.1f%%)\n", stats->tcp_count, tcp_percent);
    printf("UDP: %d (%.1f%%)\n", stats->udp_count, udp_percent);
    printf("ICMP: %d (%.1f%%)\n", stats->icmp_count, icmp_percent);
    printf("Other: %d (%.1f%%)\n", stats->other_count, other_percent);
    printf("Memory usage: %.1f KB\n", stats->memory_usage / 1024.0);
    fflush(stdout);
}

void print_final_stats(const packet_stats_t *stats) {
    if (stats == NULL) {
        return;
    }
    
    // Calculate percentages
    float tcp_percent = stats->total_packets > 0 ? 
                        (float)stats->tcp_count * 100 / stats->total_packets : 0;
    float udp_percent = stats->total_packets > 0 ? 
                        (float)stats->udp_count * 100 / stats->total_packets : 0;
    float icmp_percent = stats->total_packets > 0 ? 
                         (float)stats->icmp_count * 100 / stats->total_packets : 0;
    float other_percent = stats->total_packets > 0 ? 
                          (float)stats->other_count * 100 / stats->total_packets : 0;
    
    printf("\nFinal Statistics:\n");
    printf("[%ld seconds elapsed]\n", time(NULL) - stats->start_time);
    printf("Packets captured: %d\n", stats->total_packets);
    printf("TCP: %d (%.1f%%)\n", stats->tcp_count, tcp_percent);
    printf("UDP: %d (%.1f%%)\n", stats->udp_count, udp_percent);
    printf("ICMP: %d (%.1f%%)\n", stats->icmp_count, icmp_percent);
    printf("Other: %d (%.1f%%)\n", stats->other_count, other_percent);
    printf("Memory usage: %.1f KB\n", stats->memory_usage / 1024.0);
    printf("Packet analyzer terminated.\n");
}