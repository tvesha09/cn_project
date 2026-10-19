#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <arpa/inet.h>
#include "lpm.h"

#define NUM_ROUTES 5000
#define NUM_QUERIES 500000

int main(void) {
    printf("====================================================\n");
    printf("  BACSE203 Project: LPM Trie Performance Benchmark  \n");
    printf("====================================================\n");

    lpm_init();

    // Populate Trie with synthetic routes
    printf("[*] Populating routing table with %d subnets...\n", NUM_ROUTES);
    for (int i = 1; i <= NUM_ROUTES; i++) {
        uint32_t net = (10 << 24) | ((i & 0xFF) << 16) | (((i >> 8) & 0xFF) << 8);
        lpm_insert(htonl(net), 24, 0, "eth1", 9002);
    }

    printf("[*] Executing %d random IP lookup queries...\n", NUM_QUERIES);

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    int matches = 0;
    for (int i = 0; i < NUM_QUERIES; i++) {
        uint32_t rand_ip = (10 << 24) | ((i % 256) << 16) | (((i / 256) % 256) << 8) | (i & 0xFF);
        lpm_node_t *res = lpm_lookup_fast(htonl(rand_ip));
        if (res) matches++;
    }

    clock_gettime(CLOCK_MONOTONIC, &end);

    double total_sec = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
    double latency_ns = (total_sec / NUM_QUERIES) * 1e9;
    double throughput_mpps = (NUM_QUERIES / total_sec) / 1e6;

    printf("\n=== Performance Results ===\n");
    printf("Matched Packets : %d / %d\n", matches, NUM_QUERIES);
    printf("Total Execution : %.4f seconds\n", total_sec);
    printf("Average Latency : %.2f nanoseconds per lookup\n", latency_ns);
    printf("Throughput      : %.2f Million Lookups/sec (Mpps)\n", throughput_mpps);
    printf("===========================\n");

    lpm_free();
    return 0;
}