#include <stddef.h>
#include <arpa/inet.h>

#include "packet.h"
#include "checksum.h"

uint16_t packet_checksum_compute(const router_packet_t *pkt)
{
    router_packet_t copy = *pkt;

    copy.checksum = 0;

    return compute_checksum(
        &copy,
        offsetof(router_packet_t, payload)
    );
}

void packet_checksum_update(router_packet_t *pkt)
{
    pkt->checksum = htons(packet_checksum_compute(pkt));
}

int packet_checksum_verify(const router_packet_t *pkt)
{
    router_packet_t copy = *pkt;
    uint16_t stored = pkt->checksum;

    copy.checksum = 0;

    return htons(compute_checksum(
        &copy,
        offsetof(router_packet_t, payload)
    )) == stored;
}
