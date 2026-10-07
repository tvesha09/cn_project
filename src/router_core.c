#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "packet.h"
#include "lpm.h"
#include "arp.h"
#include "interfaces.h"


void packet_handler(int sock_fd, const char *iface, void *buf, int len)
{
    /* Make sure the received data is large enough */
    if (len < (int)sizeof(router_packet_t)) {
        printf("[DROP] Packet too small\n");
        return;
    }

    router_packet_t *pkt = (router_packet_t *)buf;

    /* 1. Check packet magic */
    if (pkt->magic != PACKET_MAGIC) {
        printf("[DROP] Invalid packet magic\n");
        return;
    }

    printf("\n[INGRESS] Packet received on %s | TTL=%d\n",
           iface, pkt->ttl);

    /* 2. TTL processing */
    if (pkt->ttl <= 1) {
        printf("[DROP] TTL expired (TTL=%d)\n", pkt->ttl);
        return;
    }

    pkt->ttl--;

    printf("[TTL] TTL decremented: New TTL=%d\n", pkt->ttl);

    /* 3. Longest Prefix Match */
    route_entry_t *route = lpm_lookup(pkt->dst_ip);

    if (route == NULL) {
        printf("[DROP] No route for destination IP\n");
        return;
    }

    printf("[LPM] Destination matched route: %s -> %s\n",
           route->iface,
           inet_ntoa(*(struct in_addr *)&route->network));

    /* 4. Determine target IP */
    uint32_t target_ip;

    if (route->next_hop != 0)
        target_ip = route->next_hop;
    else
        target_ip = pkt->dst_ip;

    /* 5. ARP lookup */
    uint8_t next_mac[6];
    int dest_port;

    if (!arp_lookup(target_ip, next_mac, &dest_port)) {
        printf("[DROP] ARP resolution failed\n");
        return;
    }

    printf("[ARP] MAC resolved, destination UDP port=%d\n",
           dest_port);

    /* 6. Update destination MAC */
    memcpy(pkt->dst_mac, next_mac, 6);

    /* 7. Forward packet */
    struct sockaddr_in dest_addr;

    memset(&dest_addr, 0, sizeof(dest_addr));

    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(dest_port);
    inet_pton(AF_INET, "127.0.0.1", &dest_addr.sin_addr);

    ssize_t sent = sendto(
        sock_fd,
        pkt,
        sizeof(router_packet_t),
        0,
        (struct sockaddr *)&dest_addr,
        sizeof(dest_addr)
    );

    if (sent < 0) {
        perror("[ERROR] sendto");
        return;
    }

    printf("[FORWARD] Forwarded packet: %s -> UDP %d | New TTL=%d\n",
           route->iface,
           dest_port,
           pkt->ttl);
}