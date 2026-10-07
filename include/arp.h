#ifndef ARP_H
#define ARP_H

#include <stdint.h>

typedef struct {
    uint32_t ip;
    uint8_t mac[6];
    int host_port;
} arp_entry_t;

void arp_init(void);

void arp_add(const char *ip_str, const uint8_t *mac, int host_port);

int arp_lookup(uint32_t ip, uint8_t *out_mac, int *out_port);

#endif