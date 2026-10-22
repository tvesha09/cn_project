#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "packet.h"
#include "icmp.h"

#define ROUTER_PORT 8001
#define CLIENT_PORT 9001

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

    if (icmp_checksum(response.payload, response.payload_len) != 0) {
        printf("[FAIL] Invalid simulated ICMP checksum\n");
        return -1;
    }
    printf("[PASS] Simulated ICMP checksum valid\n");

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

    struct timeval timeout = {3, 0};

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

int main(void) {
    printf("=== Dynamic ARP Test Simulation ===\n\n");

    // Phase 1: Send packet without ARP entry (Trigger Cache Miss & ARP Request)
    printf("[*] Step 1: Sending data packet to 192.168.2.20 (Cache Miss Expected)...\n");
    send_data_packet("192.168.1.10", "192.168.2.20");

    sleep(1);

    // Phase 2: Host B sends ARP Reply back to router eth1 (Port 8002)
    printf("\n[*] Step 2: Simulating Host B answering ARP Request...\n");
    uint8_t host_b_mac[6] = {0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0x02};
    send_arp_reply("192.168.2.20", host_b_mac, 8002);

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

    // Phase 3: Send another data packet (Now it should be a Cache HIT and forward immediately)
    printf("\n[*] Step 3: Sending second packet to 192.168.2.20 (Cache Hit Expected)...\n");
    send_data_packet("192.168.1.10", "192.168.2.20");
if (send_test_packet(sock_fd, 64, "172.16.5.99") != 0 ||
    receive_icmp_response(sock_fd, ICMP_DEST_UNREACHABLE) != 0) {
    close(sock_fd);
    return 1;
}

    printf("\n=== ICMP tests completed ===\n");

    close(sock_fd);
    return 0;
}
