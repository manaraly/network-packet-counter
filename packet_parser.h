#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H

#include <pcap.h>
#include <stdint.h>
#include <time.h>

/* Ethernet header */
struct eth_header {
    u_char ether_dhost[6]; /* Destination host address */
    u_char ether_shost[6]; /* Source host address */
    u_short ether_type;    /* IP? ARP? RARP? etc */
};

/* IP header */
struct ip_header {
    u_char ip_vhl;        /* version << 4 | header length >> 2 */
    u_char ip_tos;        /* type of service */
    u_short ip_len;       /* total length */
    u_short ip_id;        /* identification */
    u_short ip_off;       /* fragment offset field */
    u_char ip_ttl;        /* time to live */
    u_char ip_p;          /* protocol */
    u_short ip_sum;       /* checksum */
    struct in_addr ip_src, ip_dst; /* source and dest address */
};
#define IP_HL(ip)       (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)        (((ip)->ip_vhl) >> 4)

/* Protocol numbers */
#define IPPROTO_TCP     6   /* TCP protocol */
#define IPPROTO_UDP     17  /* UDP protocol */
#define IPPROTO_ICMP    1   /* ICMP protocol */

/* Protocol types for get_packet_protocol function */
#define PROTO_TCP       1
#define PROTO_UDP       2
#define PROTO_ICMP      3
#define PROTO_OTHER     4

/* Packet statistics structure */
typedef struct {
    int tcp_count;
    int udp_count;
    int icmp_count;
    int other_count;
    int total_packets;
    time_t start_time;
    size_t memory_usage;
} packet_stats_t;

/* Initialize packet stats */
void init_packet_stats(packet_stats_t *stats);

/* Process a packet and update stats */
void process_packet(const u_char *packet, struct pcap_pkthdr *header, packet_stats_t *stats);

/* Get protocol from packet */
int get_packet_protocol(const u_char *packet, struct pcap_pkthdr *header);

/* Print current statistics */
void print_stats(const packet_stats_t *stats);

/* Print final statistics */
void print_final_stats(const packet_stats_t *stats);

#endif /* PACKET_PARSER_H */