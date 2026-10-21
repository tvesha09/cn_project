
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include "packet.h"

#define ROUTER_PORT 8001

static void send_test_packet(int sock_fd, uint8_t ttl,
                             const char *dst_ip) {
    router_packet_t pkt;
    memset(&pkt, 0, sizeof(pkt));

    pkt.magic = PACKET_MAGIC;
    pkt.ttl = ttl;
    inet_pton(AF_INET, "192.168.1.10", &pkt.src_ip);
    inet_pton(AF_INET, dst_ip, &pkt.dst_ip);

    const char *payload = "TEST PACKET";
    pkt.payload_len = strlen(payload);
    memcpy(pkt.payload, payload, pkt.payload_len);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(ROUTER_PORT);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

    if (sendto(sock_fd, &pkt, sizeof(pkt), 0,
               (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("sendto");
        return;
    }

    printf("[TEST] Sent destination=%s TTL=%u\n", dst_ip, ttl);
}

int main(void) {
    int sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock_fd < 0) {
        perror("socket");
        return 1;
    }

    printf("=== Router Test Client ===\n");

    printf("\nTEST 1: Normal forwarding\n");
    send_test_packet(sock_fd, 64, "192.168.2.20");
    sleep(1);

    printf("\nTEST 2: TTL expiry\n");
    send_test_packet(sock_fd, 1, "192.168.2.20");
    sleep(1);

    printf("\nTEST 3: ARP cache miss\n");
    send_test_packet(sock_fd, 64, "192.168.2.99");
    sleep(1);

    close(sock_fd);
    return 0;
}
