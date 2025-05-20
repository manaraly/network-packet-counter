#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include "packet_parser.h"

// Mock packet creation helper functions
void create_eth_header(struct eth_header *eth, u_short ether_type) {
    memset(eth, 0, sizeof(struct eth_header));
    eth->ether_type = htons(ether_type);
}

void create_ip_header(struct ip_header *ip, u_char protocol) {
    memset(ip, 0, sizeof(struct ip_header));
    ip->ip_vhl = 0x45;  // IPv4, 5 × 32-bit words in header
    ip->ip_len = htons(sizeof(struct ip_header) + 20);  // IP header + dummy payload
    ip->ip_p = protocol;
}

// Test case 1: Basic Protocol Identification
void test_protocol_identification() {
    printf("Running Test Case 1: Basic Protocol Identification\n");
    
    // Allocate memory for test packets and headers
    u_char *tcp_packet = (u_char *)malloc(1500);
    u_char *udp_packet = (u_char *)malloc(1500);
    u_char *icmp_packet = (u_char *)malloc(1500);
    u_char *other_packet = (u_char *)malloc(1500);
    struct pcap_pkthdr header;
    
    if (!tcp_packet || !udp_packet || !icmp_packet || !other_packet) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(1);
    }
    
    // Set up capture header
    memset(&header, 0, sizeof(struct pcap_pkthdr));
    header.caplen = 1500;
    header.len = 1500;
    
    // Create TCP packet
    struct eth_header *eth = (struct eth_header *)tcp_packet;
    struct ip_header *ip = (struct ip_header *)(tcp_packet + sizeof(struct eth_header));
    
    create_eth_header(eth, ETHERTYPE_IP);
    create_ip_header(ip, IPPROTO_TCP);
    
    // Create UDP packet
    eth = (struct eth_header *)udp_packet;
    ip = (struct ip_header *)(udp_packet + sizeof(struct eth_header));
    
    create_eth_header(eth, ETHERTYPE_IP);
    create_ip_header(ip, IPPROTO_UDP);
    
    // Create ICMP packet
    eth = (struct eth_header *)icmp_packet;
    ip = (struct ip_header *)(icmp_packet + sizeof(struct eth_header));
    
    create_eth_header(eth, ETHERTYPE_IP);
    create_ip_header(ip, IPPROTO_ICMP);
    
    // Create non-IP packet
    eth = (struct eth_header *)other_packet;
    create_eth_header(eth, ETHERTYPE_ARP);
    
    // Test protocol identification
    assert(get_packet_protocol(tcp_packet, &header) == PROTO_TCP);
    assert(get_packet_protocol(udp_packet, &header) == PROTO_UDP);
    assert(get_packet_protocol(icmp_packet, &header) == PROTO_ICMP);
    assert(get_packet_protocol(other_packet, &header) == PROTO_OTHER);
    
    printf("Test Case 1: Basic Protocol Identification - PASSED\n");
    
    // Clean up
    free(tcp_packet);
    free(udp_packet);
    free(icmp_packet);
    free(other_packet);
}

// Test case 2: Edge Case Handling
void test_edge_case_handling() {
    printf("Running Test Case 2: Edge Case Handling\n");
    
    // Allocate memory for test packet and header
    u_char *packet = (u_char *)malloc(1500);
    struct pcap_pkthdr header;
    
    if (!packet) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(1);
    }
    
    // Set up capture header
    memset(&header, 0, sizeof(struct pcap_pkthdr));
    header.caplen = 1500;
    header.len = 1500;
    
    // Test 1: NULL packet
    assert(get_packet_protocol(NULL, &header) == PROTO_OTHER);
    
    // Test 2: NULL header
    assert(get_packet_protocol(packet, NULL) == PROTO_OTHER);
    
    // Test 3: Invalid IP header length
    struct eth_header *eth = (struct eth_header *)packet;
    struct ip_header *ip = (struct ip_header *)(packet + sizeof(struct eth_header));
    
    create_eth_header(eth, ETHERTYPE_IP);
    create_ip_header(ip, IPPROTO_TCP);
    ip->ip_vhl = 0x41;  // IPv4, 1 × 32-bit word in header (invalid)
    
    assert(get_packet_protocol(packet, &header) == PROTO_OTHER);
    
    // Test 4: Truncated packet
    create_eth_header(eth, ETHERTYPE_IP);
    create_ip_header(ip, IPPROTO_TCP);
    header.caplen = sizeof(struct eth_header) + 4;  // Truncated IP header
    
    assert(get_packet_protocol(packet, &header) == PROTO_OTHER);
    
    // Test 5: Unknown IP protocol
    header.caplen = 1500;
    create_eth_header(eth, ETHERTYPE_IP);
    create_ip_header(ip, 100);  // Some unusual protocol number
    
    assert(get_packet_protocol(packet, &header) == PROTO_OTHER);
    
    printf("Test Case 2: Edge Case Handling - PASSED\n");
    
    // Clean up
    free(packet);
}

// Test case 3: Statistics updates
void test_stats_updates() {
    printf("Running Test Case 3: Statistics Updates\n");
    
    // Allocate memory for test packets and header
    u_char *tcp_packet = (u_char *)malloc(1500);
    struct pcap_pkthdr header;
    packet_stats_t stats;
    
    if (!tcp_packet) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(1);
    }
    
    // Set up capture header
    memset(&header, 0, sizeof(struct pcap_pkthdr));
    header.caplen = 1500;
    header.len = 1500;
    
    // Create TCP packet
    struct eth_header *eth = (struct eth_header *)tcp_packet;
    struct ip_header *ip = (struct ip_header *)(tcp_packet + sizeof(struct eth_header));
    
    create_eth_header(eth, ETHERTYPE_IP);
    create_ip_header(ip, IPPROTO_TCP);
    
    // Initialize stats
    init_packet_stats(&stats);
    
    // Test that initial stats are zero
    assert(stats.tcp_count == 0);
    assert(stats.udp_count == 0);
    assert(stats.icmp_count == 0);
    assert(stats.other_count == 0);
    assert(stats.total_packets == 0);
    
    // Process TCP packet
    process_packet(tcp_packet, &header, &stats);
    
    // Verify stats updated correctly
    assert(stats.tcp_count == 1);
    assert(stats.udp_count == 0);
    assert(stats.icmp_count == 0);
    assert(stats.other_count == 0);
    assert(stats.total_packets == 1);
    
    // Modify packet to UDP
    ip->ip_p = IPPROTO_UDP;
    process_packet(tcp_packet, &header, &stats);
    
    // Verify stats updated correctly
    assert(stats.tcp_count == 1);
    assert(stats.udp_count == 1);
    assert(stats.icmp_count == 0);
    assert(stats.other_count == 0);
    assert(stats.total_packets == 2);
    
    // Modify packet to ICMP
    ip->ip_p = IPPROTO_ICMP;
    process_packet(tcp_packet, &header, &stats);
    
    // Verify stats updated correctly
    assert(stats.tcp_count == 1);
    assert(stats.udp_count == 1);
    assert(stats.icmp_count == 1);
    assert(stats.other_count == 0);
    assert(stats.total_packets == 3);
    
    // Modify packet to Other
    create_eth_header(eth, ETHERTYPE_ARP);
    process_packet(tcp_packet, &header, &stats);
    
    // Verify stats updated correctly
    assert(stats.tcp_count == 1);
    assert(stats.udp_count == 1);
    assert(stats.icmp_count == 1);
    assert(stats.other_count == 1);
    assert(stats.total_packets == 4);
    
    printf("Test Case 3: Statistics Updates - PASSED\n");
    
    // Clean up
    free(tcp_packet);
}

int main() {
    printf("Running packet_parser tests\n");
    printf("============================\n\n");
    
    // Run test cases
    test_protocol_identification();
    printf("\n");
    
    test_edge_case_handling();
    printf("\n");
    
    test_stats_updates();
    printf("\n");
    
    printf("All tests PASSED\n");
    
    return 0;
}