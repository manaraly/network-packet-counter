#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include "packet_parser.h"

#define PCAP_BUFFER_SIZE 65536
#define PCAP_TIMEOUT 1000  // milliseconds
#define DEFAULT_STATS_INTERVAL 5  // seconds

// Global variables
static int running = 1;
static pcap_t *handle = NULL;
static packet_stats_t stats;
static time_t next_stats_time = 0;

// Signal handler for CTRL+C
void signal_handler(int signum) {
    running = 0;
    printf("\nReceived signal %d, shutting down...\n", signum);
}

// Callback function for pcap_dispatch
void packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet) {
    packet_stats_t *stats = (packet_stats_t *)user;
    
    // Process the packet
    process_packet(packet, (struct pcap_pkthdr *)header, stats);
    
    // Check if it's time to print stats
    time_t current_time = time(NULL);
    if (current_time >= next_stats_time) {
        print_stats(stats);
        next_stats_time = current_time + DEFAULT_STATS_INTERVAL;
    }
}

// Print usage information
void print_usage(const char *program_name) {
    printf("Usage: %s -i <interface> [-f <filter>] [-t <seconds>]\n", program_name);
    printf("  -i <interface> : Network interface to capture from (required)\n");
    printf("  -f <filter>    : BPF filter expression (optional)\n");
    printf("  -t <seconds>   : Duration to run in seconds (optional, default: run until CTRL+C)\n");
}

int main(int argc, char *argv[]) {
    char *interface = NULL;
    char *filter = NULL;
    int duration = 0;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    int opt;
    
    // Parse command line arguments
    while ((opt = getopt(argc, argv, "i:f:t:h")) != -1) {
        switch (opt) {
            case 'i':
                interface = optarg;
                break;
            case 'f':
                filter = optarg;
                break;
            case 't':
                duration = atoi(optarg);
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }
    
    // Check if interface is specified
    if (interface == NULL) {
        fprintf(stderr, "Error: Interface not specified\n");
        print_usage(argv[0]);
        return 1;
    }
    
    // Initialize packet stats
    init_packet_stats(&stats);
    
    // Set up signal handler for CTRL+C
    signal(SIGINT, signal_handler);
    
    // Open the network interface for packet capture
    handle = pcap_open_live(interface, PCAP_BUFFER_SIZE, 1, PCAP_TIMEOUT, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening interface %s: %s\n", interface, errbuf);
        return 2;
    }
    
    // Set the filter if specified
    if (filter != NULL) {
        bpf_u_int32 net, mask;
        
        if (pcap_lookupnet(interface, &net, &mask, errbuf) == -1) {
            fprintf(stderr, "Warning: Could not get netmask for interface %s: %s\n", 
                    interface, errbuf);
            net = 0;
            mask = 0;
        }
        
        if (pcap_compile(handle, &fp, filter, 0, net) == -1) {
            fprintf(stderr, "Error compiling filter '%s': %s\n", 
                    filter, pcap_geterr(handle));
            pcap_close(handle);
            return 3;
        }
        
        if (pcap_setfilter(handle, &fp) == -1) {
            fprintf(stderr, "Error setting filter: %s\n", pcap_geterr(handle));
            pcap_freecode(&fp);
            pcap_close(handle);
            return 4;
        }
        
        pcap_freecode(&fp);
    }
    
    // Print initial information
    printf("Packet Analyzer (E-VAS Tel Team)\n");
    printf("---------------------------------\n");
    printf("Interface: %s\n", interface);
    printf("Buffer Size: %d packets\n", PCAP_BUFFER_SIZE);
    printf("Filter: %s\n", filter ? filter : "none");
    printf("Duration: %d seconds\n", duration > 0 ? duration : 0);
    printf("Output File: none\n");
    
    // Set the start time for statistics
    next_stats_time = time(NULL) + DEFAULT_STATS_INTERVAL;
    
    // Calculate end time if duration is specified
    time_t end_time = 0;
    if (duration > 0) {
        end_time = time(NULL) + duration;
    }
    
    // Start packet capture loop
    while (running) {
        // Process packets in batches
        int packets_processed = pcap_dispatch(handle, -1, packet_handler, (u_char *)&stats);
        
        // Check for errors
        if (packets_processed < 0) {
            fprintf(stderr, "Error capturing packets: %s\n", pcap_geterr(handle));
            break;
        }
        
        // Check if we need to stop based on duration
        if (duration > 0 && time(NULL) >= end_time) {
            printf("\nDuration reached, shutting down...\n");
            break;
        }
        
        // Small sleep to prevent CPU hogging
        usleep(100);
    }
    
    // Print final statistics
    print_final_stats(&stats);
    
    // Clean up
    pcap_close(handle);
    
    return 0;
}