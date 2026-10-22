#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "packet.h"
#include "lpm.h"
#include "arp.h"
#include "checksum.h"
#include "interfaces.h"
#include "icmp.h"

static uint32_t router_ip_for_iface(const char *iface)
{
    struct in_addr addr;

    const char *ip = "10.0.0.1";

    if (strcmp(iface, "eth0") == 0) {
        ip = "192.168.1.1";
    } else if (strcmp(iface, "eth1") == 0) {
        ip = "192.168.2.1";
    }

    if (inet_pton(AF_INET, ip, &addr) != 1) {
        return 0;
    }

    return addr.s_addr;
}

static void send_icmp_error(
    int sock_fd,
    const char *iface,
    const router_packet_t *original,
    uint8_t type,
    uint8_t code)
{
    uint8_t source_mac[6];
    int source_port;

    if (!arp_lookup(original->src_ip, source_mac, &source_port)) {
        printf("[ICMP] Cannot reply: source host is not in ARP cache\n");
        return;
    }

    router_packet_t response;

    if (icmp_build_error(
            &response,
            original,
            type,
            code,
            router_ip_for_iface(iface)) != 0) {
        printf("[ICMP] Failed to build error response\n");
        return;
    }

    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));

    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(source_port);
    inet_pton(AF_INET, "127.0.0.1", &dest_addr.sin_addr);

    ssize_t sent = sendto(
        sock_fd,
        &response,
        sizeof(response),
        0,
        (struct sockaddr *)&dest_addr,
        sizeof(dest_addr));

    if (sent < 0) {
        perror("[ICMP] sendto failed");
        return;
    }

    printf("[ICMP] Error response sent to UDP port %d\n", source_port);
}

static void send_icmp_echo_reply(
    int sock_fd,
    const router_packet_t *request)
{
    uint8_t source_mac[6];
    int source_port;

    if (!arp_lookup(request->src_ip, source_mac, &source_port)) {
        printf("[ICMP] Cannot send Echo Reply: source not in ARP cache\n");
        return;
    }

    router_packet_t response;

    if (icmp_build_echo_reply(&response, request) != 0) {
        printf("[ICMP] Invalid Echo Request\n");
        return;
    }

    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));

    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(source_port);
    dest_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    ssize_t sent = sendto(
        sock_fd,
        &response,
        sizeof(response),
        0,
        (struct sockaddr *)&dest_addr,
        sizeof(dest_addr));

    if (sent != (ssize_t)sizeof(response)) {
        perror("[ICMP] Echo Reply sendto failed");
        return;
    }

    printf("[ICMP] Echo Reply sent to UDP port %d\n", source_port);
}



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
    
/* Handle an ICMP Echo Request addressed to this router. */
if (pkt->payload_len >= sizeof(icmp_header_t) &&
    pkt->payload_len <= MAX_PAYLOAD_LEN) {

    icmp_header_t icmp_request;
    memcpy(&icmp_request, pkt->payload, sizeof(icmp_request));

    if (icmp_request.type == ICMP_ECHO_REQUEST &&
        icmp_request.code == 0 &&
        pkt->dst_ip == router_ip_for_iface(iface)) {

        printf("[ICMP] Echo Request received for router\n");

        send_icmp_echo_reply(sock_fd, pkt);
        return;
    }
}


    /* 2. TTL processing */

    if (pkt->ttl <= 1) 
    {
    printf("[DROP] TTL expired (TTL=%d)\n", pkt->ttl);

    send_icmp_error(
        sock_fd,
        iface,
        pkt,
        ICMP_TIME_EXCEEDED,
        ICMP_CODE_TTL_EXPIRED
    );

    return;
    }
    pkt->ttl--;

    printf("[TTL] TTL decremented: New TTL=%d\n", pkt->ttl);

    /* 3. Longest Prefix Match */
    route_entry_t *route = lpm_lookup(pkt->dst_ip);
if (route == NULL) {
    printf("[DROP] No route for destination IP\n");

    send_icmp_error(
        sock_fd,
        iface,
        pkt,
        ICMP_DEST_UNREACHABLE,
        ICMP_CODE_NET_UNREACHABLE
    );

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
