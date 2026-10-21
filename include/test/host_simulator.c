
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include "arp_protocol.h"

#define HOST_PORT 9001

int main(void) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return 1;
    }

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(HOST_PORT);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(sock);
        return 1;
    }

    printf("[HOST] Listening on UDP port %d\n", HOST_PORT);

    while (1) {
        arp_message_t msg;
        struct sockaddr_in sender;
        socklen_t sender_len = sizeof(sender);

        ssize_t n = recvfrom(sock, &msg, sizeof(msg), 0,
                             (struct sockaddr *)&sender, &sender_len);

        if (n != sizeof(msg) || msg.magic != ARP_MESSAGE_MAGIC)
            continue;

        if (msg.operation != ARP_REQUEST ||
            msg.target_ip != inet_addr("192.168.1.10"))
            continue;

        printf("[ARP] Request received for 192.168.1.10\n");

        uint32_t requester_ip = msg.sender_ip;
        uint8_t requester_mac[6];
        memcpy(requester_mac, msg.sender_mac, 6);

        memset(&msg, 0, sizeof(msg));
        msg.magic = ARP_MESSAGE_MAGIC;
        msg.operation = ARP_REPLY;
        msg.sender_ip = inet_addr("192.168.1.10");
        msg.target_ip = requester_ip;

        uint8_t host_mac[6] = {
            0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0x01
        };
        memcpy(msg.sender_mac, host_mac, 6);
        memcpy(msg.target_mac, requester_mac, 6);
        msg.sender_port = HOST_PORT;

        if (sendto(sock, &msg, sizeof(msg), 0,
                   (struct sockaddr *)&sender, sender_len) < 0) {
            perror("[ARP] sendto");
            continue;
        }

        printf("[ARP] Reply sent for 192.168.1.10\n");
    }

    close(sock);
    return 0;
}
