
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include "arp.h"

#define MAX_ARP 32
#define ARP_CACHE_TIMEOUT 60

static arp_entry_t arp_cache[MAX_ARP];
static int arp_count = 0;

void arp_init(void) {
    arp_count = 0;

    /*
     * Keep the Review 1 simulated hosts for backward
     * compatibility. Dynamic ARP handling will be added
     * through the router interface module.
     */
    uint8_t mac_a[6] = {0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0x01};
    uint8_t mac_b[6] = {0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0x02};

    arp_add("192.168.1.10", mac_a, 9001);
    arp_add("192.168.2.20", mac_b, 9002);
}

void arp_add(const char *ip_str, const uint8_t *mac, int host_port) {
    uint32_t ip;

    if (ip_str == NULL || mac == NULL) {
        return;
    }

    if (inet_pton(AF_INET, ip_str, &ip) != 1) {
        return;
    }

    time_t now = time(NULL);

    /* Update an existing entry instead of creating a duplicate. */
    for (int i = 0; i < arp_count; i++) {
        if (arp_cache[i].ip == ip) {
            memcpy(arp_cache[i].mac, mac, 6);
            arp_cache[i].host_port = host_port;
            arp_cache[i].last_updated = (uint64_t)now;
            return;
        }
    }

    /* If full, reuse an expired entry before dropping the update. */
    int slot = -1;

    for (int i = 0; i < arp_count; i++) {
        if (now - (time_t)arp_cache[i].last_updated >=
            ARP_CACHE_TIMEOUT) {
            slot = i;
            break;
        }
    }

    if (slot == -1) {
        if (arp_count >= MAX_ARP) {
            return;
        }
        slot = arp_count++;
    }

    arp_cache[slot].ip = ip;
    memcpy(arp_cache[slot].mac, mac, 6);
    arp_cache[slot].host_port = host_port;
    arp_cache[slot].last_updated = (uint64_t)now;
}

int arp_lookup(uint32_t ip, uint8_t *out_mac, int *out_port) {
    if (out_mac == NULL || out_port == NULL) {
        return 0;
    }

    time_t now = time(NULL);
    
    for (int i = 0; i < arp_count; i++) {
        if (arp_cache[i].ip == ip) {
            if (now - (time_t)arp_cache[i].last_updated >=
                ARP_CACHE_TIMEOUT) {
                /* Remove the expired entry by shifting later entries. */
                for (int j = i; j < arp_count - 1; j++) {
                    arp_cache[j] = arp_cache[j + 1];
                }

                arp_count--;
                return 0;
            }

            memcpy(out_mac, arp_cache[i].mac, 6);
            *out_port = arp_cache[i].host_port;
            return 1;
        }
    }

    return 0;
}
