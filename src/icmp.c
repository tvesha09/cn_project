
#include "icmp.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <arpa/inet.h>

/*
 * Calculate the Internet checksum over an ICMP message.
 * The result is returned in host byte order.
 */
uint16_t icmp_checksum(const void *data, size_t length)
{
    if (data == NULL) {
        return 0;
    }

    const uint8_t *bytes = (const uint8_t *)data;
    uint32_t sum = 0;

    /* Add 16-bit words in network byte order. */
    while (length >= 2) {
        sum += ((uint32_t)bytes[0] << 8) | bytes[1];
        bytes += 2;
        length -= 2;
    }

    /* Handle an odd number of bytes. */
    if (length == 1) {
        sum += (uint32_t)bytes[0] << 8;
    }

    /* Fold carries into the lower 16 bits. */
    while (sum >> 16) {
        sum = (sum & 0xFFFFU) + (sum >> 16);
    }

    /* Return the one's complement. */
    return (uint16_t)(~sum & 0xFFFFU);
}

/*
 * Build a simulated ICMP Echo Reply.
 *
 * The request payload must contain an ICMP Echo Request
 * header followed by its data.
 */
int icmp_build_echo_reply(
    router_packet_t *response,
    const router_packet_t *request)
{
    if (response == NULL || request == NULL) {
        return -1;
    }

    if (request->magic != PACKET_MAGIC ||
        request->payload_len < sizeof(icmp_header_t) ||
        request->payload_len > MAX_PAYLOAD_LEN) {
        return -1;
    }

    /* Copy first so that response and request may safely alias. */
    router_packet_t original = *request;
    icmp_header_t header;

    memcpy(&header, original.payload, sizeof(header));

    if (header.type != ICMP_ECHO_REQUEST || header.code != 0) {
        return -1;
    }

    /* Start with the original simulated packet. */
    *response = original;

    /* Reverse simulated IP and MAC addresses. */
    response->src_ip = original.dst_ip;
    response->dst_ip = original.src_ip;

    memcpy(response->src_mac, original.dst_mac, 6);
    memcpy(response->dst_mac, original.src_mac, 6);

    response->ttl = 64;

    /* Change Echo Request to Echo Reply. */
    header.type = ICMP_ECHO_REPLY;
    header.code = 0;
    header.checksum = 0;

    memcpy(response->payload, &header, sizeof(header));

    /* Calculate checksum over the complete ICMP message. */
    uint16_t checksum =
        htons(icmp_checksum(response->payload, response->payload_len));

    memcpy(
        response->payload + offsetof(icmp_header_t, checksum),
        &checksum,
        sizeof(checksum)
    );

    return 0;
}

/*
 * Build a simulated ICMP error response.
 *
 * This project uses a custom router_packet_t format.
 * The original simulated packet is included as a quote.
 * This is not a standard raw IPv4 ICMP packet builder.
 *
 * router_ip must use the same byte order as packet IP fields.
 */
int icmp_build_error(
    router_packet_t *response,
    const router_packet_t *original,
    uint8_t type,
    uint8_t code,
    uint32_t router_ip)
{
    if (response == NULL || original == NULL) {
        return -1;
    }

    if (original->magic != PACKET_MAGIC ||
        original->payload_len > MAX_PAYLOAD_LEN) {
        return -1;
    }

    if (type != ICMP_TIME_EXCEEDED &&
        type != ICMP_DEST_UNREACHABLE) {
        return -1;
    }

    /* Preserve the original in case the pointers alias. */
    router_packet_t original_copy = *original;

    memset(response, 0, sizeof(*response));

    response->magic = PACKET_MAGIC;
    response->ttl = 64;

    /* Build the simulated return path to the original sender. */
    response->src_ip = router_ip;
    response->dst_ip = original_copy.src_ip;

    memcpy(response->src_mac, original_copy.dst_mac, 6);
    memcpy(response->dst_mac, original_copy.src_mac, 6);

    icmp_header_t header;
    memset(&header, 0, sizeof(header));

    header.type = type;
    header.code = code;
    header.checksum = 0;
    header.rest_of_header = 0;

    /* Reserve space for the ICMP header and quote the packet. */
    size_t available =
        MAX_PAYLOAD_LEN - sizeof(icmp_header_t);

    size_t quote_length = sizeof(original_copy);

    if (quote_length > available) {
        quote_length = available;
    }

    memcpy(response->payload, &header, sizeof(header));

    memcpy(
        response->payload + sizeof(header),
        &original_copy,
        quote_length
    );

    response->payload_len =
        (uint16_t)(sizeof(header) + quote_length);

    /* Calculate checksum over the entire simulated ICMP message. */
    uint16_t checksum =
        htons(icmp_checksum(response->payload, response->payload_len));

    memcpy(
        response->payload + offsetof(icmp_header_t, checksum),
        &checksum,
        sizeof(checksum)
    );

    return 0;
}
