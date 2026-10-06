#ifndef LPM_H
#define LPM_H

#include <stdint.h>

typedef struct {
    uint32_t network;      // Network IP in network byte order
    uint32_t mask;         // Subnet mask in network byte order
    uint32_t next_hop;     // Next-hop IP (0 if directly connected)
    char     iface[16];    // Egress interface name
    int      egress_port;  // Target UDP port for simulated forwarding
} route_entry_t;

void lpm_init(void);
void lpm_add_route(const char *net_str, const char *mask_str, const char *gw_str, const char *iface, int port);
route_entry_t* lpm_lookup(uint32_t dest_ip);

#endif