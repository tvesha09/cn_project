#include "checksum.h"

uint16_t compute_checksum(const void *buf, size_t len) {
    const uint16_t *data = (const uint16_t *)buf;
    uint32_t sum = 0;

    while (len > 1) {
        sum += *data++;
        len -= 2;
    }

    // Handle odd trailing byte
    if (len == 1) {
        sum += *(const uint8_t *)data;
    }

    // Fold 32-bit sum into 16 bits
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return (uint16_t)(~sum);
}

int verify_checksum(const void *buf, size_t len) {
    return compute_checksum(buf, len) == 0;
}