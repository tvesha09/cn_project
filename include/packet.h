#ifndef PACKET_H
#define PACKET_H

#include <stdint.h>

#define PACKET_MAGIC 0x4E455432 // "NET2" magic identifier
#define MAX_PAYLOAD_LEN 256

#pragma pack(push, 1)
typedef struct {
    uint32_t magic;
    uint8_t  ttl;
    uint8_t  src_mac[6];
    uint8_t  dst_mac[6];
    uint32_t src_ip;        // Stored in network byte order
    uint32_t dst_ip;        // Stored in network byte order
    uint16_t payload_len;
    char     payload[MAX_PAYLOAD_LEN];
} router_packet_t;
#pragma pack(pop)

#endif