#include "checksum.h"

uint16_t compute_checksum(const void *buf, size_t len) {
    const uint8_t *data = (const uint8_t *)buf;
    uint32_t sum = 0;

    while (len > 1) {
        sum += ((uint32_t)data[0] << 8) | data[1];
        data += 2;
        len -= 2;
    }

    // Handle odd trailing byte
    if (len == 1) {
        sum += (uint32_t)data[0] << 8;
    }

    // Fold 32-bit sum into 16 bits
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return (uint16_t)(~sum & 0xFFFF);
}

int verify_checksum(const void *buf, size_t len) {
    return compute_checksum(buf, len) == 0;
}
