
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include "arp.h"

int main(void) {
    uint8_t mac1[6] = {0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0x01};
    uint8_t mac2[6] = {0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0x03};
    uint8_t result_mac[6];
    int port = 0;

    arp_init();

    uint32_t ip = inet_addr("10.0.0.5");

    printf("TEST 1: Unknown IP\n");
    if (!arp_lookup(ip, result_mac, &port))
        printf("PASS: Unknown IP not found\n");
    else
        printf("FAIL: Unexpected cache hit\n");

    printf("\nTEST 2: Insert entry\n");
    arp_add("10.0.0.5", mac1, 9005);
    if (arp_lookup(ip, result_mac, &port) &&
        memcmp(result_mac, mac1, 6) == 0 && port == 9005)
        printf("PASS: Entry inserted and retrieved\n");
    else
        printf("FAIL: Entry insertion failed\n");

    printf("\nTEST 3: Update existing entry\n");
    arp_add("10.0.0.5", mac2, 9010);
    if (arp_lookup(ip, result_mac, &port) &&
        memcmp(result_mac, mac2, 6) == 0 && port == 9010)
        printf("PASS: Existing entry updated\n");
    else
        printf("FAIL: Entry update failed\n");

    return 0;
}
