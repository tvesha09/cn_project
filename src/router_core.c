#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "packet.h"
#include "lpm.h"
#include "arp.h"
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

    send_icmp_error(
        sock_fd,
        iface,
        pkt,
        ICMP_DEST_UNREACHABLE,
        1
    );

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