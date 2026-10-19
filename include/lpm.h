#ifndef LPM_H
#define LPM_H

#include <stdint.h>

typedef struct lpm_node {
    struct lpm_node *child[2]; // child[0] for bit 0, child[1] for bit 1
    uint32_t network;          // Subnet network IP
    uint32_t next_hop;         // Next-hop IP (0 if direct)
    char     iface[16];        // Egress interface name
    int      egress_port;      // Egress UDP port
    uint8_t  prefix_len;
    int      is_terminal;      // 1 if a route prefix terminates here
} lpm_node_t;

// Backward-compatible alias for router_core.c
typedef lpm_node_t route_entry_t;

void lpm_init(void);
void lpm_insert(uint32_t network_net_order, uint8_t prefix_len, uint32_t next_hop_net_order, const char *iface, int egress_port);
lpm_node_t* lpm_lookup_fast(uint32_t dest_ip_net_order);
void lpm_free(void);

// Inline backward-compatible wrapper for old lpm_lookup calls
static inline route_entry_t* lpm_lookup(uint32_t dest_ip_net_order) {
    return lpm_lookup_fast(dest_ip_net_order);
}

#endif // LPM_H