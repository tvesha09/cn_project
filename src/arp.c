#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include "arp.h"

#define MAX_ARP 32
static dynamic_arp_entry_t arp_cache[MAX_ARP];
static pending_packet_t    packet_queue[MAX_QUEUED_PKTS];

// Broadcast MAC address (FF:FF:FF:FF:FF:FF)
static const uint8_t BROADCAST_MAC[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
static const uint8_t ROUTER_MAC[6]    = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};

void arp_init(void) {
    memset(arp_cache, 0, sizeof(arp_cache));
    memset(packet_queue, 0, sizeof(packet_queue));
    printf("[ARP] Dynamic ARP Cache and Packet Queue initialized (TTL: %ds)\n", ARP_CACHE_TTL_SEC);
}

void arp_cache_insert(uint32_t ip, const uint8_t *mac, int host_port) {
    time_t now = time(NULL);
    int free_slot = -1;

    // Check if entry already exists (update it)
    for (int i = 0; i < MAX_ARP; i++) {
        if (arp_cache[i].is_valid && arp_cache[i].ip == ip) {
            memcpy(arp_cache[i].mac, mac, 6);
            arp_cache[i].host_port = host_port;
            arp_cache[i].last_updated = now;
            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &ip, ip_str, sizeof(ip_str));
            printf("[ARP] Cache updated for IP %s -> %02X:%02X:%02X:%02X:%02X:%02X (Port %d)\n",
                   ip_str, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], host_port);
            return;
        }
        if (!arp_cache[i].is_valid && free_slot == -1) {
            free_slot = i;
        }
    }

    if (free_slot != -1) {
        arp_cache[free_slot].ip = ip;
        memcpy(arp_cache[free_slot].mac, mac, 6);
        arp_cache[free_slot].host_port = host_port;
        arp_cache[free_slot].last_updated = now;
        arp_cache[free_slot].is_valid = 1;

        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &ip, ip_str, sizeof(ip_str));
        printf("[ARP] New cache entry added: %s -> %02X:%02X:%02X:%02X:%02X:%02X (Port %d)\n",
               ip_str, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], host_port);
    }
}

int arp_cache_lookup(uint32_t ip, uint8_t *out_mac, int *out_port) {
    time_t now = time(NULL);

    for (int i = 0; i < MAX_ARP; i++) {
        if (arp_cache[i].is_valid && arp_cache[i].ip == ip) {
            // Expiration Check
            if (difftime(now, arp_cache[i].last_updated) > ARP_CACHE_TTL_SEC) {
                char ip_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &ip, ip_str, sizeof(ip_str));
                printf("[ARP] Cache entry EXPIRED for IP %s! Triggering fresh resolution.\n", ip_str);
                arp_cache[i].is_valid = 0;
                return 0; // Expired -> Treat as cache miss
            }
            memcpy(out_mac, arp_cache[i].mac, 6);
            *out_port = arp_cache[i].host_port;
            return 1; // Valid hit
        }
    }
    return 0; // Miss
}

// Queue packet while waiting for ARP resolution
int arp_queue_packet(int sock_fd, const char *iface, uint32_t target_ip, const router_packet_t *pkt) {
    for (int i = 0; i < MAX_QUEUED_PKTS; i++) {
        if (!packet_queue[i].in_use) {
            packet_queue[i].in_use = 1;
            packet_queue[i].sock_fd = sock_fd;
            packet_queue[i].target_ip = target_ip;
            packet_queue[i].queued_time = time(NULL);
            strncpy(packet_queue[i].egress_iface, iface, sizeof(packet_queue[i].egress_iface) - 1);
            memcpy(&packet_queue[i].pkt, pkt, sizeof(router_packet_t));

            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &target_ip, ip_str, sizeof(ip_str));
            printf("[ARP] Queued packet waiting for resolution of IP %s\n", ip_str);
            return 1;
        }
    }
    printf("[ARP] Drop: Packet queue full\n");
    return 0;
}

// Send an ARP Request broadcast to the simulated interface
void arp_send_request(int sock_fd, const char *iface, uint32_t target_ip, int broadcast_port) {
    router_packet_t req;
    memset(&req, 0, sizeof(req));

    req.magic = PACKET_MAGIC;
    req.pkt_type = PKT_TYPE_ARP_REQ;
    req.ttl = 1;
    memcpy(req.src_mac, ROUTER_MAC, 6);
    memcpy(req.dst_mac, BROADCAST_MAC, 6);
    req.dst_ip = target_ip;
    snprintf(req.payload, sizeof(req.payload), "ARP Who-Has Request");
    req.payload_len = strlen(req.payload);

    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(broadcast_port);
    inet_pton(AF_INET, "127.0.0.1", &dest.sin_addr);

    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &target_ip, ip_str, sizeof(ip_str));
    printf("[ARP] Broadcasted ARP Request on %s: 'Who has %s?' -> Port %d\n", iface, ip_str, broadcast_port);

    sendto(sock_fd, &req, sizeof(req), 0, (struct sockaddr *)&dest, sizeof(dest));
}

// Flush and send all packets that were queued waiting for this IP
void arp_send_queued_packets(int sock_fd, uint32_t ip, const uint8_t *mac, int port) {
    for (int i = 0; i < MAX_QUEUED_PKTS; i++) {
        if (packet_queue[i].in_use && packet_queue[i].target_ip == ip) {
            router_packet_t *pkt = &packet_queue[i].pkt;
            memcpy(pkt->dst_mac, mac, 6);

            struct sockaddr_in dest;
            memset(&dest, 0, sizeof(dest));
            dest.sin_family = AF_INET;
            dest.sin_port = htons(port);
            inet_pton(AF_INET, "127.0.0.1", &dest.sin_addr);

            sendto(sock_fd, pkt, sizeof(router_packet_t), 0, (struct sockaddr *)&dest, sizeof(dest));
            printf("[ARP] Flushed queued packet -> Delivered to Port %d with MAC %02X:%02X:%02X:%02X:%02X:%02X\n",
                   port, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

            packet_queue[i].in_use = 0;
        }
    }
}

// When router receives an ARP Reply from a host
void arp_handle_reply(int sock_fd, const router_packet_t *pkt, int sender_port) {
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &pkt->src_ip, ip_str, sizeof(ip_str));

    printf("[ARP] Received ARP Reply from %s (MAC: %02X:%02X:%02X:%02X:%02X:%02X, Port: %d)\n",
           ip_str, pkt->src_mac[0], pkt->src_mac[1], pkt->src_mac[2], pkt->src_mac[3], pkt->src_mac[4], pkt->src_mac[5], sender_port);

    // 1. Insert into cache
    arp_cache_insert(pkt->src_ip, pkt->src_mac, sender_port);

    // 2. Transmit queued packets
    arp_send_queued_packets(sock_fd, pkt->src_ip, pkt->src_mac, sender_port);
}
