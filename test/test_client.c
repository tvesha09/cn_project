#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <pthread.h>

#include "packet.h"
#include "icmp.h"
#include "arp.h"

#define ROUTER_PORT 8001
#define CLIENT_PORT 9001
#define FORWARD_PORT 9002
#define DYNAMIC_HOST_PORT 9010
#define DYNAMIC_HOST_IP "192.168.2.30"

static const uint8_t dynamic_host_mac[6] =
    {0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0x30};

static void *arp_responder_thread(void *arg)
{
    (void)arg;

    int sock_fd = socket(AF_INET, SOCK_DGRAM, 0);

    if (sock_fd < 0) {
        perror("[FAIL] ARP responder socket");
        return NULL;
    }

    int reuse = 1;
    setsockopt(
        sock_fd,
        SOL_SOCKET,
        SO_REUSEADDR,
        &reuse,
        sizeof(reuse));

    struct sockaddr_in arp_addr;
    memset(&arp_addr, 0, sizeof(arp_addr));

    arp_addr.sin_family = AF_INET;
    arp_addr.sin_port = htons(ARP_BROADCAST_PORT);
    arp_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(
            sock_fd,
            (struct sockaddr *)&arp_addr,
            sizeof(arp_addr)) < 0) {
        perror("[FAIL] bind ARP responder");
        close(sock_fd);
        return NULL;
    }

    uint32_t dynamic_ip;
    inet_pton(AF_INET, DYNAMIC_HOST_IP, &dynamic_ip);

    printf("[TEST] ARP responder listening on UDP %d\n",
           ARP_BROADCAST_PORT);

    while (1) {
        router_packet_t request;
        struct sockaddr_in sender;
        socklen_t sender_len = sizeof(sender);

        ssize_t received = recvfrom(
            sock_fd,
            &request,
            sizeof(request),
            0,
            (struct sockaddr *)&sender,
            &sender_len);

        if (received != (ssize_t)sizeof(request) ||
            request.magic != PACKET_MAGIC ||
            !packet_checksum_verify(&request)) {
            continue;
        }

        arp_message_t msg;

        if (!arp_parse_message(
                request.payload,
                request.payload_len,
                &msg)) {
            continue;
        }

        if (msg.opcode != ARP_OP_REQUEST || msg.target_ip != dynamic_ip) {
            continue;
        }

        router_packet_t reply;
        memset(&reply, 0, sizeof(reply));

        reply.magic = PACKET_MAGIC;
        reply.ttl = 1;
        memcpy(reply.src_mac, dynamic_host_mac, 6);
        memcpy(reply.dst_mac, msg.sender_mac, 6);
        reply.src_ip = dynamic_ip;
        reply.dst_ip = msg.sender_ip;
        reply.payload_len = sizeof(arp_message_t);

        arp_message_t response;
        memset(&response, 0, sizeof(response));

        response.magic = ARP_MAGIC;
        response.opcode = ARP_OP_REPLY;
        memcpy(response.sender_mac, dynamic_host_mac, 6);
        response.sender_ip = dynamic_ip;
        response.sender_port = DYNAMIC_HOST_PORT;
        response.target_ip = msg.sender_ip;

        memcpy(reply.payload, &response, sizeof(response));
        packet_checksum_update(&reply);

        if (sendto(
                sock_fd,
                &reply,
                sizeof(reply),
                0,
                (struct sockaddr *)&sender,
                sender_len) != (ssize_t)sizeof(reply)) {
            perror("[FAIL] ARP reply sendto");
            continue;
        }

        printf("[TEST] ARP reply sent for %s\n", DYNAMIC_HOST_IP);
    }

    close(sock_fd);
    return NULL;
}

static int open_data_socket(int port)
{
    int sock_fd = socket(AF_INET, SOCK_DGRAM, 0);

    if (sock_fd < 0) {
        perror("[FAIL] data socket");
        return -1;
    }

    struct timeval timeout = {5, 0};

    setsockopt(
        sock_fd,
        SOL_SOCKET,
        SO_RCVTIMEO,
        &timeout,
        sizeof(timeout));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(
            sock_fd,
            (struct sockaddr *)&addr,
            sizeof(addr)) < 0) {
        perror("[FAIL] bind data socket");
        close(sock_fd);
        return -1;
    }

    return sock_fd;
}

static int send_test_packet(
    int sock_fd,
    uint8_t ttl,
    const char *dst_ip)
{
    router_packet_t pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.magic = PACKET_MAGIC;
    pkt.ttl = ttl;

    if (inet_pton(AF_INET, "192.168.1.10", &pkt.src_ip) != 1 ||
        inet_pton(AF_INET, dst_ip, &pkt.dst_ip) != 1) {
        fprintf(stderr, "[FAIL] Invalid IP address\n");
        return -1;
    }

    const char payload[] = "TEST PACKET";
    pkt.payload_len = (uint16_t)(sizeof(payload) - 1);
    memcpy(pkt.payload, payload, sizeof(payload) - 1);
    packet_checksum_update(&pkt);

    struct sockaddr_in router_addr;
    memset(&router_addr, 0, sizeof(router_addr));

    router_addr.sin_family = AF_INET;
    router_addr.sin_port = htons(ROUTER_PORT);
    router_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    ssize_t sent = sendto(
        sock_fd,
        &pkt,
        sizeof(pkt),
        0,
        (struct sockaddr *)&router_addr,
        sizeof(router_addr));

    if (sent != (ssize_t)sizeof(pkt)) {
        perror("[FAIL] sendto");
        return -1;
    }

    printf("[TEST] Sent packet: destination=%s TTL=%u\n",
           dst_ip, (unsigned)ttl);

    return 0;
}

static int receive_forwarded_packet(
    int sock_fd,
    const char *expected_ip,
    uint8_t expected_ttl)
{
    router_packet_t forwarded;
    struct sockaddr_in sender;
    socklen_t sender_len = sizeof(sender);

    printf("[TEST] Waiting for forwarded packet...\n");

    ssize_t received = recvfrom(
        sock_fd,
        &forwarded,
        sizeof(forwarded),
        0,
        (struct sockaddr *)&sender,
        &sender_len);

    if (received != (ssize_t)sizeof(forwarded) ||
        forwarded.magic != PACKET_MAGIC ||
        !packet_checksum_verify(&forwarded)) {
        printf("[FAIL] Invalid forwarded packet\n");
        return -1;
    }

    uint32_t expected;

    if (inet_pton(AF_INET, expected_ip, &expected) != 1 ||
        forwarded.dst_ip != expected ||
        forwarded.ttl != expected_ttl) {
        printf("[FAIL] Forwarded packet did not match expectation\n");
        return -1;
    }

    printf("[PASS] Forwarded packet received with TTL=%u\n",
           (unsigned)forwarded.ttl);

    return 0;
}

static int receive_icmp_response(
    int sock_fd,
    uint8_t expected_type)
{
    router_packet_t response;
    struct sockaddr_in sender;
    socklen_t sender_len = sizeof(sender);

    printf("[TEST] Waiting for ICMP response...\n");

    ssize_t received = recvfrom(
        sock_fd,
        &response,
        sizeof(response),
        0,
        (struct sockaddr *)&sender,
        &sender_len);

    if (received < 0) {
        perror("[FAIL] Receiving ICMP response");
        return -1;
    }

    if (received != (ssize_t)sizeof(response) ||
        response.magic != PACKET_MAGIC ||
        response.payload_len < sizeof(icmp_header_t) ||
        response.payload_len > MAX_PAYLOAD_LEN) {
        printf("[FAIL] Invalid simulated ICMP packet\n");
        return -1;
    }

    if (!packet_checksum_verify(&response)) {
        printf("[FAIL] Invalid simulated packet checksum\n");
        return -1;
    }

    if (icmp_checksum(response.payload, response.payload_len) != 0) {
        printf("[FAIL] Invalid simulated ICMP checksum\n");
        return -1;
    }
    printf("[PASS] Simulated packet and ICMP checksums valid\n");

    icmp_header_t header;
    memcpy(&header, response.payload, sizeof(header));

    printf("[RECEIVED] ICMP type=%u code=%u\n",
           (unsigned)header.type,
           (unsigned)header.code);

    if (header.type != expected_type) {
        printf("[FAIL] Expected ICMP type %u, received %u\n",
               (unsigned)expected_type,
               (unsigned)header.type);
        return -1;
    }

    if (header.type == ICMP_TIME_EXCEEDED && header.code == 0) {
        printf("[PASS] ICMP Time Exceeded received\n");
        return 0;
    }

    if (header.type == ICMP_ECHO_REPLY && header.code == 0) {
        printf("[PASS] ICMP Echo Reply received\n");
        return 0;
    }

    if (header.type == ICMP_DEST_UNREACHABLE) {
        printf("[INFO] ICMP Destination Unreachable received\n");
        return 0;
    }

    printf("[FAIL] Unexpected ICMP code\n");
    return -1;
}

static int send_echo_request(int sock_fd)
{
    router_packet_t pkt;
    memset(&pkt, 0, sizeof(pkt));

    pkt.magic = PACKET_MAGIC;
    pkt.ttl = 64;

    if (inet_pton(AF_INET, "192.168.1.10", &pkt.src_ip) != 1 ||
        inet_pton(AF_INET, "192.168.1.1", &pkt.dst_ip) != 1) {
        fprintf(stderr, "[FAIL] Invalid Echo Request IP\n");
        return -1;
    }

    icmp_header_t header;
    memset(&header, 0, sizeof(header));

    header.type = ICMP_ECHO_REQUEST;
    header.code = 0;
    header.rest_of_header = htonl(0x12340001);

    memcpy(pkt.payload, &header, sizeof(header));
    memcpy(pkt.payload + sizeof(header), "PING", 4);

    pkt.payload_len = (uint16_t)(sizeof(header) + 4);

    uint16_t checksum =
        htons(icmp_checksum(pkt.payload, pkt.payload_len));

    memcpy(pkt.payload + 2, &checksum, sizeof(checksum));
    packet_checksum_update(&pkt);

    struct sockaddr_in router_addr;
    memset(&router_addr, 0, sizeof(router_addr));

    router_addr.sin_family = AF_INET;
    router_addr.sin_port = htons(ROUTER_PORT);
    router_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    ssize_t sent = sendto(
        sock_fd,
        &pkt,
        sizeof(pkt),
        0,
        (struct sockaddr *)&router_addr,
        sizeof(router_addr));

    if (sent != (ssize_t)sizeof(pkt)) {
        perror("[FAIL] Sending Echo Request");
        return -1;
    }

    printf("[TEST] ICMP Echo Request sent to 192.168.1.1\n");
    return 0;
}

int main(void)
{
    int sock_fd = socket(AF_INET, SOCK_DGRAM, 0);

    if (sock_fd < 0) {
        perror("[FAIL] socket");
        return 1;
    }

    struct timeval timeout = {5, 0};

    if (setsockopt(
            sock_fd,
            SOL_SOCKET,
            SO_RCVTIMEO,
            &timeout,
            sizeof(timeout)) < 0) {
        perror("[FAIL] setsockopt");
        close(sock_fd);
        return 1;
    }

    struct sockaddr_in client_addr;
    memset(&client_addr, 0, sizeof(client_addr));

    client_addr.sin_family = AF_INET;
    client_addr.sin_port = htons(CLIENT_PORT);
    client_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (bind(
            sock_fd,
            (struct sockaddr *)&client_addr,
            sizeof(client_addr)) < 0) {
        perror("[FAIL] bind client socket");
        close(sock_fd);
        return 1;
    }

    pthread_t arp_thread;

    if (pthread_create(
            &arp_thread,
            NULL,
            arp_responder_thread,
            NULL) != 0) {
        perror("[FAIL] pthread_create ARP responder");
        close(sock_fd);
        return 1;
    }

    pthread_detach(arp_thread);
    usleep(200000);

    printf("=== Router Test Client ===\n");

    printf("\nTEST 1: Normal forwarding\n");

    int forward_fd = open_data_socket(FORWARD_PORT);

    if (forward_fd < 0 ||
        send_test_packet(sock_fd, 64, "192.168.2.20") != 0 ||
        receive_forwarded_packet(forward_fd, "192.168.2.20", 63) != 0) {
        if (forward_fd >= 0) {
            close(forward_fd);
        }
        close(sock_fd);
        return 1;
    }

    close(forward_fd);

    printf("\nTEST 2: TTL Exceeded\n");

    if (send_test_packet(sock_fd, 1, "192.168.2.20") != 0 ||
        receive_icmp_response(sock_fd, ICMP_TIME_EXCEEDED) != 0) {
        close(sock_fd);
        return 1;
    }

    printf("\nTEST 3: ICMP Echo Reply\n");

    if (send_echo_request(sock_fd) != 0 ||
        receive_icmp_response(sock_fd, ICMP_ECHO_REPLY) != 0) {
        close(sock_fd);
        return 1;
    }

    printf("\nTEST 4: Destination Unreachable\n");

    if (send_test_packet(sock_fd, 64, "172.16.5.99") != 0 ||
        receive_icmp_response(sock_fd, ICMP_DEST_UNREACHABLE) != 0) {
        close(sock_fd);
        return 1;
    }

    printf("\nTEST 5: Dynamic ARP, queueing, and forwarded packet\n");

    int dynamic_fd = open_data_socket(DYNAMIC_HOST_PORT);

    if (dynamic_fd < 0 ||
        send_test_packet(sock_fd, 64, DYNAMIC_HOST_IP) != 0 ||
        receive_forwarded_packet(
            dynamic_fd,
            DYNAMIC_HOST_IP,
            63) != 0) {
        if (dynamic_fd >= 0) {
            close(dynamic_fd);
        }
        close(sock_fd);
        return 1;
    }

    close(dynamic_fd);

    printf("\n=== ICMP and forwarding tests completed ===\n");

    close(sock_fd);
    return 0;
}