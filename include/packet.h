#ifndef PACKET_H
#define PACKET_H

#include <stdint.h>

#define PACKET_MAGIC 0x4E455432 // "NET2"
#define MAX_PAYLOAD_LEN 256

// Packet Types
#define PKT_TYPE_DATA       1
#define PKT_TYPE_ARP_REQ    2
#define PKT_TYPE_ARP_REPLY  3

#pragma pack(push, 1)
typedef struct {
    uint32_t magic;                    // Packet identifier
    uint8_t  pkt_type;                 // PKT_TYPE_DATA, PKT_TYPE_ARP_REQ, etc.
    uint8_t  ttl;                      // Time to Live
    uint16_t checksum;                 // Internet Checksum
    uint8_t  src_mac[6];
    uint8_t  dst_mac[6];
    uint32_t src_ip;                   // Network byte order
    uint32_t dst_ip;                   // Network byte order
    uint16_t payload_len;
    char     payload[MAX_PAYLOAD_LEN];
} router_packet_t;
#pragma pack(pop)

#endif // PACKET_H
