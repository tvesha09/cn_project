
#ifndef ARP_H
#define ARP_H

#include <stdint.h>

typedef struct {
    uint32_t ip;
    uint8_t mac[6];
    int host_port;
    uint64_t last_updated;
} arp_entry_t;

void arp_init(void);

void arp_add(const char *ip_str, const uint8_t *mac, int host_port);

int arp_lookup(uint32_t ip, uint8_t *out_mac, int *out_port);

#define ARP_REQUEST 1
#define ARP_REPLY 2

int arp_is_resolved(uint32_t ip);

#endif
