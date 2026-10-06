#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "arp.h"

#define MAX_ARP 32
static arp_entry_t arp_cache[MAX_ARP];
static int arp_count = 0;

void arp_init(void) {
    arp_count = 0;
    // Pre-populate simulated host entries for Review 1
    uint8_t mac_a[6] = {0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0x01};
    uint8_t mac_b[6] = {0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0x02};
    arp_add("192.168.1.10", mac_a, 9001);
    arp_add("192.168.2.20", mac_b, 9002);
}

void arp_add(const char *ip_str, const uint8_t *mac, int host_port) {
    if (arp_count >= MAX_ARP) return;
    arp_entry_t *entry = &arp_cache[arp_count++];
    inet_pton(AF_INET, ip_str, &entry->ip);
    memcpy(entry->mac, mac, 6);
    entry->host_port = host_port;
}

int arp_lookup(uint32_t ip, uint8_t *out_mac, int *out_port) {
    for (int i = 0; i < arp_count; i++) {
        if (arp_cache[i].ip == ip) {
            memcpy(out_mac, arp_cache[i].mac, 6);
            *out_port = arp_cache[i].host_port;
            return 1; // Success: Resolved
        }
    }
    return 0; // Miss: IP not found
}