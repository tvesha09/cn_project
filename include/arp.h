#ifndef ARP_H
#define ARP_H

#include <stdint.h>
#include <stddef.h>
#include <time.h>
#include "packet.h"

#define ARP_MAGIC              0x41525032u
#define ARP_OP_REQUEST         1
#define ARP_OP_REPLY           2
#define ARP_BROADCAST_PORT     9000
#define ARP_CACHE_TTL_SEC      30
#define ARP_MAX_PENDING        16
#define ARP_PENDING_TIMEOUT    3
#define ARP_RETRY_INTERVAL     1
#define ARP_MAX_RETRIES        2

#pragma pack(push, 1)
typedef struct {
    uint32_t magic;
    uint8_t  opcode;
    uint8_t  sender_mac[6];
    uint32_t sender_ip;
    int32_t  sender_port;
    uint32_t target_ip;
} arp_message_t;
#pragma pack(pop)

// Dynamic ARP Cache Entry
typedef struct {
    uint32_t ip;               // Network byte order
    uint8_t  mac[6];
    int      host_port;        // Target UDP port for simulated node
    time_t   last_seen;        // Timestamp for expiration
    int      is_valid;         // 1 if active, 0 if empty/expired
} arp_entry_t;

// Initialization & Maintenance
void arp_init(void);
void arp_expire(void);

// Cache Operations
void arp_cache_insert(uint32_t ip, const uint8_t *mac, int host_port);
void arp_add_entry(uint32_t ip, const uint8_t *mac, int host_port);
void arp_add(const char *ip_str, const uint8_t *mac, int port);
int  arp_cache_lookup(uint32_t ip, uint8_t *out_mac, int *out_port);
int  arp_lookup(uint32_t ip, uint8_t *out_mac, int *out_port);

// Protocol Parsing
int  arp_parse_message(const void *buf, size_t len, arp_message_t *out);

#endif // ARP_H