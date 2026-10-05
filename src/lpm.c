#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "lpm.h"

#define MAX_ROUTES 32

static route_entry_t routing_table[MAX_ROUTES];
static int route_count = 0;

void lpm_init(void) {
    route_count = 0;
    // Default direct subnets
    lpm_add_route("192.168.1.0", "255.255.255.0", NULL, "eth0", 9001);
    lpm_add_route("192.168.2.0", "255.255.255.0", NULL, "eth1", 9002);
    // Default route (0.0.0.0/0)
    lpm_add_route("0.0.0.0", "0.0.0.0", "10.0.0.254", "eth2", 9003);
}

void lpm_add_route(const char *net_str, const char *mask_str, const char *gw_str, const char *iface, int port) {
    if (route_count >= MAX_ROUTES) return;
    route_entry_t *r = &routing_table[route_count++];
    inet_pton(AF_INET, net_str, &r->network);
    inet_pton(AF_INET, mask_str, &r->mask);
    if (gw_str) inet_pton(AF_INET, gw_str, &r->next_hop);
    else r->next_hop = 0;
    strncpy(r->iface, iface, sizeof(r->iface) - 1);
    r->egress_port = port;
}

route_entry_t* lpm_lookup(uint32_t dest_ip) {
    route_entry_t *best_match = NULL;
    uint32_t highest_mask = 0;

    for (int i = 0; i < route_count; i++) {
        // Bitwise check: (dest_ip & mask) == network_ip
        if ((dest_ip & routing_table[i].mask) == routing_table[i].network) {
            uint32_t cur_mask = ntohl(routing_table[i].mask);
            if (cur_mask >= highest_mask) {
                highest_mask = cur_mask;
                best_match = &routing_table[i];
            }
        }
    }
    return best_match;
}