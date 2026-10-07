#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

#include "packet.h"

#define ROUTER_PORT 8001

void send_test_packet(int sock_fd, uint8_t ttl, const char *dst_ip)
{
    router_packet_t pkt;

    memset(&pkt, 0, sizeof(pkt));

    pkt.magic = PACKET_MAGIC;
    pkt.ttl = ttl;

    inet_pton(AF_INET, "192.168.1.10", &pkt.src_ip);
    inet_pton(AF_INET, dst_ip, &pkt.dst_ip);

    pkt.payload_len = strlen("TEST PACKET");
    strcpy(pkt.payload, "TEST PACKET");

    struct sockaddr_in router_addr;

    memset(&router_addr, 0, sizeof(router_addr));

    router_addr.sin_family = AF_INET;
    router_addr.sin_port = htons(ROUTER_PORT);
    inet_pton(AF_INET, "127.0.0.1", &router_addr.sin_addr);

    sendto(
        sock_fd,
        &pkt,
        sizeof(pkt),
        0,
        (struct sockaddr *)&router_addr,
        sizeof(router_addr)
    );

    printf("[TEST] Sent packet: destination=%s TTL=%d\n",
           dst_ip, ttl);
}

int main(void)
{
    int sock_fd;

    sock_fd = socket(AF_INET, SOCK_DGRAM, 0);

    if (sock_fd < 0) {
        perror("socket");
        return 1;
    }

    printf("=== Router Test Client ===\n");

    /* Test 1: Normal packet */
    printf("\nTEST 1: Normal forwarding\n");
    send_test_packet(sock_fd, 64, "192.168.2.20");

    sleep(1);

    /* Test 2: TTL expiry */
    printf("\nTEST 2: TTL expiry\n");
    send_test_packet(sock_fd, 1, "192.168.2.20");

    sleep(1);

    close(sock_fd);

    return 0;
}