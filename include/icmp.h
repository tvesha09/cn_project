#ifndef ICMP_H
#define ICMP_H

#include <stdint.h>
#include <stddef.h>
#include "packet.h"

/* ICMP message types */
#define ICMP_ECHO_REPLY        0
#define ICMP_DEST_UNREACHABLE  3
#define ICMP_ECHO_REQUEST      8
#define ICMP_TIME_EXCEEDED     11

/* Common ICMP error codes */
#define ICMP_CODE_NET_UNREACHABLE   0
#define ICMP_CODE_HOST_UNREACHABLE  1
#define ICMP_CODE_TTL_EXPIRED       0

/* Standard 8-byte ICMP header */
typedef struct {
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;
    uint32_t rest_of_header;
} icmp_header_t;

/* Calculate the ICMP checksum */
uint16_t icmp_checksum(const void *data, size_t length);

/* Build an Echo Reply */
int icmp_build_echo_reply(
    router_packet_t *response,
    const router_packet_t *request
);

/* Build an ICMP error response */
int icmp_build_error(
    router_packet_t *response,
    const router_packet_t *original,
    uint8_t type,
    uint8_t code,
    uint32_t router_ip
);

#endif