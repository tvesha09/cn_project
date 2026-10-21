#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "packet.h"

void send_data_packet(const char *src_ip, const char *dst_ip) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(8001); // Ingress on eth0
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

    router_packet_t pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.magic = PACKET_MAGIC;
    pkt.pkt_type = PKT_TYPE_DATA;
    pkt.ttl = 64;
    inet_pton(AF_INET, src_ip, &pkt.src_ip);
    inet_pton(AF_INET, dst_ip, &pkt.dst_ip);
    snprintf(pkt.payload, sizeof(pkt.payload), "Hello via Dynamic ARP!");
    pkt.payload_len = strlen(pkt.payload);

    sendto(fd, &pkt, sizeof(pkt), 0, (struct sockaddr *)&addr, sizeof(addr));
    close(fd);
}

void send_arp_reply(const char *host_ip, const uint8_t *mac, int router_port) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(router_port);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

    router_packet_t reply;
    memset(&reply, 0, sizeof(reply));
    reply.magic = PACKET_MAGIC;
    reply.pkt_type = PKT_TYPE_ARP_REPLY;
    reply.ttl = 1;
    memcpy(reply.src_mac, mac, 6);
    inet_pton(AF_INET, host_ip, &reply.src_ip);

    printf("[HOST B] Sending ARP Reply: '%s is at %02X:%02X:%02X:%02X:%02X:%02X'\n",
           host_ip, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    sendto(fd, &reply, sizeof(reply), 0, (struct sockaddr *)&addr, sizeof(addr));
    close(fd);
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

    sleep(1);

    // Phase 3: Send another data packet (Now it should be a Cache HIT and forward immediately)
    printf("\n[*] Step 3: Sending second packet to 192.168.2.20 (Cache Hit Expected)...\n");
    send_data_packet("192.168.1.10", "192.168.2.20");

    return 0;
}
