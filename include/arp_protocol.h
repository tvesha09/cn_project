
#ifndef ARP_PROTOCOL_H
#define ARP_PROTOCOL_H

#include <stdint.h>

#define ARP_MESSAGE_MAGIC 0x41525031
#define ARP_REQUEST 1
#define ARP_REPLY 2

typedef struct {
    uint32_t magic;
    uint8_t operation;
    uint32_t sender_ip;
    uint32_t target_ip;
    uint8_t sender_mac[6];
    uint8_t target_mac[6];
    int32_t sender_port;
} arp_message_t;

#endif
