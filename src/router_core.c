#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "packet.h"
#include "lpm.h"
#include "arp.h"
#include "checksum.h"

void process_packet(int sock_fd, const char *in_iface, void *buf, int len) {
    if (len < (int)sizeof(router_packet_t)) return;

    router_packet_t *pkt = (router_packet_t *)buf;
    if (pkt->magic != PACKET_MAGIC) return;

    // 1. Handle incoming ARP Replies from hosts
    if (pkt->pkt_type == PKT_TYPE_ARP_REPLY) {
        // Find sender port based on IP or sender
        int reply_port = 9002; // Default simulated host port
        arp_handle_reply(sock_fd, pkt, reply_port);
        return;
    }

    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &pkt->src_ip, src_ip, sizeof(src_ip));
    inet_ntop(AF_INET, &pkt->dst_ip, dst_ip, sizeof(dst_ip));

    printf("\n[%s] Ingress packet: %s -> %s (TTL: %d)\n", in_iface, src_ip, dst_ip, pkt->ttl);

    // 2. TTL Check
    if (pkt->ttl <= 1) {
        printf("[%s] [DROP] TTL expired (TTL=%d)\n", in_iface, pkt->ttl);
        return;
    }
    pkt->ttl -= 1;

    // 3. Routing Table Lookup (Member 2's Trie)
    lpm_node_t *route = lpm_lookup_fast(pkt->dst_ip);
    if (!route) {
        printf("[%s] [DROP] No route to destination %s\n", in_iface, dst_ip);
        return;
    }

    uint32_t target_ip = (route->next_hop != 0) ? route->next_hop : pkt->dst_ip;

    // 4. Dynamic ARP Lookup (Member 1's Module)
    uint8_t next_mac[6];
    int dest_port = 0;

    if (!arp_cache_lookup(target_ip, next_mac, &dest_port)) {
        // Cache Miss! Queue the data packet and broadcast an ARP Request
        printf("[%s] [ARP MISS] No MAC for %s! Queuing packet & sending ARP Request.\n", in_iface, dst_ip);
        arp_queue_packet(sock_fd, route->iface, target_ip, pkt);
        arp_send_request(sock_fd, route->iface, target_ip, route->egress_port);
        return;
    }

    // 5. Cache Hit -> Forward Immediately
    memcpy(pkt->dst_mac, next_mac, 6);

    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(dest_port);
    inet_pton(AF_INET, "127.0.0.1", &dest_addr.sin_addr);

    sendto(sock_fd, pkt, sizeof(router_packet_t), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
    printf("[%s] [FORWARD] Egress via %s to UDP Port %d (TTL: %d)\n",
           in_iface, route->iface, dest_port, pkt->ttl);
}
