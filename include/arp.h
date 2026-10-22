#ifndef ARP_H
#define ARP_H

#include <stdint.h>
#include <time.h>
#include "packet.h"

#define ARP_CACHE_TTL_SEC 30  // Entries expire after 30 seconds
#define MAX_QUEUED_PKTS   16

// Dynamic ARP Cache Entry
typedef struct {
    uint32_t ip;               // Network byte order
    uint8_t  mac[6];
    int      host_port;        // Target UDP port for simulated node
    time_t   last_updated;     // Timestamp for expiration
    int      is_valid;         // 1 if active, 0 if empty/expired
} dynamic_arp_entry_t;

// Queue for holding packets awaiting ARP resolution
typedef struct {
    uint32_t target_ip;
    int      sock_fd;
    char     egress_iface[16];
    router_packet_t pkt;
    time_t   queued_time;
    int      in_use;
} pending_packet_t;

void arp_init(void);
void arp_cache_insert(uint32_t ip, const uint8_t *mac, int host_port);
int  arp_cache_lookup(uint32_t ip, uint8_t *out_mac, int *out_port);

// Queue management for unresolved packets
int  arp_queue_packet(int sock_fd, const char *iface, uint32_t target_ip, const router_packet_t *pkt);
void arp_send_queued_packets(int sock_fd, uint32_t ip, const uint8_t *mac, int port);

// Protocol handlers
void arp_send_request(int sock_fd, const char *iface, uint32_t target_ip, int broadcast_port);
void arp_handle_reply(int sock_fd, const router_packet_t *pkt, int sender_port);

#endif // ARP_H
