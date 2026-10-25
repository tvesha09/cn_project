#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>

#include "packet.h"
#include "lpm.h"
#include "arp.h"
#include "checksum.h"
#include "interfaces.h"
#include "icmp.h"
#include "router_core.h"

/* Renamed to router_pending_pkt_t to eliminate collision with arp.h's pending_packet_t */
typedef struct {
    int used;
    router_packet_t pkt;
    uint32_t target_ip;
    int ingress_fd;
    char ingress_iface[16];
    char egress_iface[16];
    time_t queued_at;
    time_t last_request;
    int retries;
} router_pending_pkt_t;

static router_pending_pkt_t g_pending[ARP_MAX_PENDING];
static pthread_mutex_t g_pending_lock = PTHREAD_MUTEX_INITIALIZER;

static void send_icmp_error(
    int sock_fd,
    const char *iface,
    const router_packet_t *original,
    uint8_t type,
    uint8_t code);

static void send_icmp_echo_reply(
    int sock_fd,
    const router_packet_t *request);

static uint32_t router_ip_for_iface(const char *iface)
{
    struct in_addr addr;
    const char *ip = "10.0.0.1";

    if (strcmp(iface, "eth0") == 0) {
        ip = "192.168.1.1";
    } else if (strcmp(iface, "eth1") == 0) {
        ip = "192.168.2.1";
    } else if (strcmp(iface, "eth2") == 0) {
        ip = "192.168.3.1";
    }

    if (inet_pton(AF_INET, ip, &addr) != 1) {
        return 0;
    }

    return addr.s_addr;
}

static void router_mac_for_iface(const char *iface, uint8_t mac[6])
{
    memset(mac, 0, 6);
    mac[0] = 0x02;

    if (strcmp(iface, "eth0") == 0) {
        mac[5] = 0x01;
    } else if (strcmp(iface, "eth1") == 0) {
        mac[5] = 0x02;
    } else if (strcmp(iface, "eth2") == 0) {
        mac[5] = 0x03;
    } else {
        mac[5] = 0x01;
    }
}

static int iface_sock_fd(const char *iface)
{
    for (int i = 0; i < NUM_INTERFACES; i++) {
        if (strcmp(g_interfaces[i].iface_name, iface) == 0) {
            return g_interfaces[i].sock_fd;
        }
    }

    return -1;
}

static int iface_listen_port(const char *iface)
{
    for (int i = 0; i < NUM_INTERFACES; i++) {
        if (strcmp(g_interfaces[i].iface_name, iface) == 0) {
            return g_interfaces[i].listen_port;
        }
    }

    return -1;
}

static int send_arp_frame(
    int fd,
    const router_packet_t *frame)
{
    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));

    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(ARP_BROADCAST_PORT);
    dest_addr.sin_addr.s_addr = htonl(INADDR_BROADCAST);

    ssize_t sent = sendto(
        fd,
        frame,
        sizeof(*frame),
        0,
        (struct sockaddr *)&dest_addr,
        sizeof(dest_addr)
    );

    if (sent == (ssize_t)sizeof(*frame)) {
        return 2;
    }

    dest_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    sent = sendto(
        fd,
        frame,
        sizeof(*frame),
        0,
        (struct sockaddr *)&dest_addr,
        sizeof(dest_addr)
    );

    if (sent == (ssize_t)sizeof(*frame)) {
        return 1;
    }

    return 0;
}

static void send_arp_request(
    uint32_t target_ip,
    const char *egress_iface)
{
    int fd = iface_sock_fd(egress_iface);

    if (fd < 0) {
        printf("[ARP] Invalid egress interface %s\n", egress_iface);
        return;
    }

    uint8_t router_mac[6];
    router_mac_for_iface(egress_iface, router_mac);

    router_packet_t frame;
    memset(&frame, 0, sizeof(frame));

    frame.magic = PACKET_MAGIC;
    frame.ttl = 1;
    memcpy(frame.src_mac, router_mac, 6);
    memset(frame.dst_mac, 0xFF, 6);
    frame.src_ip = router_ip_for_iface(egress_iface);
    frame.dst_ip = htonl(INADDR_BROADCAST);
    frame.payload_len = sizeof(arp_message_t);

    arp_message_t msg;
    memset(&msg, 0, sizeof(msg));

    msg.magic = ARP_MAGIC;
    msg.opcode = ARP_OP_REQUEST;
    memcpy(msg.sender_mac, router_mac, 6);
    msg.sender_ip = frame.src_ip;
    msg.sender_port = iface_listen_port(egress_iface);
    msg.target_ip = target_ip;

    memcpy(frame.payload, &msg, sizeof(msg));
    packet_checksum_update(&frame);

    int result = send_arp_frame(fd, &frame);

    if (result == 0) {
        perror("[ARP] Broadcast sendto failed");
        return;
    }

    printf("[ARP] Broadcast request for %s on %s%s\n",
           inet_ntoa(*(struct in_addr *)&target_ip),
           egress_iface,
           result == 1 ? " (loopback fallback)" : "");
}

static void send_arp_reply(
    int sock_fd,
    const char *iface,
    const arp_message_t *request)
{
    uint32_t router_ip = router_ip_for_iface(iface);

    if (request->target_ip != router_ip) {
        return;
    }

    uint8_t router_mac[6];
    router_mac_for_iface(iface, router_mac);

    router_packet_t frame;
    memset(&frame, 0, sizeof(frame));

    frame.magic = PACKET_MAGIC;
    frame.ttl = 1;
    memcpy(frame.src_mac, router_mac, 6);
    memcpy(frame.dst_mac, request->sender_mac, 6);
    frame.src_ip = router_ip;
    frame.dst_ip = request->sender_ip;
    frame.payload_len = sizeof(arp_message_t);

    arp_message_t reply;
    memset(&reply, 0, sizeof(reply));

    reply.magic = ARP_MAGIC;
    reply.opcode = ARP_OP_REPLY;
    memcpy(reply.sender_mac, router_mac, 6);
    reply.sender_ip = router_ip;
    reply.sender_port = iface_listen_port(iface);
    reply.target_ip = request->sender_ip;

    memcpy(frame.payload, &reply, sizeof(reply));
    packet_checksum_update(&frame);

    if (send_arp_frame(sock_fd, &frame) == 0) {
        perror("[ARP] Reply sendto failed");
    }
}

static int queue_packet(
    int sock_fd,
    const char *iface,
    const char *egress_iface,
    const router_packet_t *pkt,
    uint32_t target_ip)
{
    int already_pending = 0;
    int slot = -1;

    pthread_mutex_lock(&g_pending_lock);

    for (int i = 0; i < ARP_MAX_PENDING; i++) {
        if (g_pending[i].used && g_pending[i].target_ip == target_ip) {
            already_pending = 1;
        }

        if (!g_pending[i].used && slot < 0) {
            slot = i;
        }
    }

    if (slot < 0) {
        pthread_mutex_unlock(&g_pending_lock);
        return 0;
    }

    router_pending_pkt_t *pending = &g_pending[slot];

    pending->used = 1;
    pending->pkt = *pkt;
    pending->target_ip = target_ip;
    pending->ingress_fd = sock_fd;
    snprintf(pending->ingress_iface, sizeof(pending->ingress_iface), "%s", iface);
    snprintf(pending->egress_iface, sizeof(pending->egress_iface), "%s", egress_iface);
    pending->queued_at = time(NULL);
    pending->last_request = pending->queued_at;
    pending->retries = 0;

    pthread_mutex_unlock(&g_pending_lock);

    if (!already_pending) {
        send_arp_request(target_ip, egress_iface);
    }

    printf("[ARP] Packet queued pending resolution for %s\n",
           inet_ntoa(*(struct in_addr *)&target_ip));

    return 1;
}

static void flush_pending(
    uint32_t ip,
    const uint8_t *mac,
    int dest_port)
{
    pthread_mutex_lock(&g_pending_lock);

    for (int i = 0; i < ARP_MAX_PENDING; i++) {
        router_pending_pkt_t *pending = &g_pending[i];

        if (!pending->used || pending->target_ip != ip) {
            continue;
        }

        int fd = iface_sock_fd(pending->egress_iface);

        if (fd < 0) {
            fd = pending->ingress_fd;
        }

        memcpy(pending->pkt.dst_mac, mac, 6);
        packet_checksum_update(&pending->pkt);

        struct sockaddr_in dest_addr;
        memset(&dest_addr, 0, sizeof(dest_addr));

        dest_addr.sin_family = AF_INET;
        dest_addr.sin_port = htons(dest_port);
        dest_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

        ssize_t sent = sendto(
            fd,
            &pending->pkt,
            sizeof(pending->pkt),
            0,
            (struct sockaddr *)&dest_addr,
            sizeof(dest_addr)
        );

        if (sent != (ssize_t)sizeof(pending->pkt)) {
            perror("[ARP] Queued packet sendto failed");
        } else {
            printf("[ARP] Queued packet forwarded via %s to UDP %d\n",
                   pending->egress_iface,
                   dest_port);
        }

        pending->used = 0;
    }

    pthread_mutex_unlock(&g_pending_lock);
}

static void process_pending_timeouts(void)
{
    time_t now = time(NULL);

    router_packet_t expired_pkts[ARP_MAX_PENDING];
    int expired_fds[ARP_MAX_PENDING];
    char expired_ifaces[ARP_MAX_PENDING][16];
    int expired_count = 0;

    pthread_mutex_lock(&g_pending_lock);

    for (int i = 0; i < ARP_MAX_PENDING; i++) {
        router_pending_pkt_t *pending = &g_pending[i];

        if (!pending->used) {
            continue;
        }

        if (now - pending->queued_at >= ARP_PENDING_TIMEOUT) {
            expired_pkts[expired_count] = pending->pkt;
            expired_fds[expired_count] = pending->ingress_fd;
            snprintf(
                expired_ifaces[expired_count],
                sizeof(expired_ifaces[expired_count]),
                "%s",
                pending->ingress_iface
            );
            expired_count++;
            pending->used = 0;
        } else if (pending->retries < ARP_MAX_RETRIES &&
                   now - pending->last_request >= ARP_RETRY_INTERVAL) {
            pending->retries++;
            pending->last_request = now;
            send_arp_request(pending->target_ip, pending->egress_iface);
        }
    }

    pthread_mutex_unlock(&g_pending_lock);

    for (int i = 0; i < expired_count; i++) {
        printf("[ARP] Resolution timeout, sending Destination Unreachable\n");
        send_icmp_error(
            expired_fds[i],
            expired_ifaces[i],
            &expired_pkts[i],
            ICMP_DEST_UNREACHABLE,
            ICMP_CODE_HOST_UNREACHABLE
        );
    }
}

static void *router_timer_thread(void *arg)
{
    (void)arg;

    while (1) {
        sleep(1);
        arp_expire();
        process_pending_timeouts();
    }

    return NULL;
}

void router_start_timer(void)
{
    pthread_t timer_thread;

    if (pthread_create(
            &timer_thread,
            NULL,
            router_timer_thread,
            NULL) != 0) {
        perror("pthread_create timer");
        return;
    }

    pthread_detach(timer_thread);
}

static int process_arp_frame(
    int sock_fd,
    const char *iface,
    const router_packet_t *pkt)
{
    arp_message_t msg;

    if (!arp_parse_message(pkt->payload, pkt->payload_len, &msg)) {
        return 0;
    }

    if (msg.opcode == ARP_OP_REPLY) {
        arp_add_entry(msg.sender_ip, msg.sender_mac, msg.sender_port);
        printf("[ARP] Reply cached: %s -> UDP %d\n",
               inet_ntoa(*(struct in_addr *)&msg.sender_ip),
               msg.sender_port);
        flush_pending(msg.sender_ip, msg.sender_mac, msg.sender_port);
    } else if (msg.opcode == ARP_OP_REQUEST) {
        send_arp_reply(sock_fd, iface, &msg);
    }

    return 1;
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

    packet_checksum_update(&response);

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

    packet_checksum_update(&response);

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

    /* 1. Check packet magic and header checksum */
    if (pkt->magic != PACKET_MAGIC) {
        printf("[DROP] Invalid packet magic\n");
        return;
    }

    if (!packet_checksum_verify(pkt)) {
        printf("[DROP] Invalid packet checksum\n");
        return;
    }

    printf("\n[INGRESS] Packet received on %s | TTL=%d\n", iface, pkt->ttl);

    if (process_arp_frame(sock_fd, iface, pkt)) {
        return;
    }

    /* Handle an ICMP Echo Request addressed to this router */
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
    if (pkt->ttl <= 1) {
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

    /* 4. Dynamic ARP Lookup */
    uint8_t next_mac[6];
    int dest_port = 0;

    if (!arp_cache_lookup(target_ip, next_mac, &dest_port)) {
        printf("[ARP MISS] Queuing packet & sending ARP request for %s\n",
               inet_ntoa(*(struct in_addr *)&target_ip));

        if (!queue_packet(sock_fd, iface, route->iface, pkt, target_ip)) {
            printf("[DROP] ARP pending queue full\n");
            send_icmp_error(
                sock_fd,
                iface,
                pkt,
                ICMP_DEST_UNREACHABLE,
                ICMP_CODE_HOST_UNREACHABLE
            );
        }
        return;
    }

    printf("[ARP] MAC resolved, destination UDP port=%d\n", dest_port);

    /* 5. Update destination MAC & recalculate checksum */
    memcpy(pkt->dst_mac, next_mac, 6);
    packet_checksum_update(pkt);

    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(dest_port);
    dest_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

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