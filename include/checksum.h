#ifndef CHECKSUM_H
#define CHECKSUM_H

#include <stdint.h>
#include <stddef.h>

// Calculates RFC 1071 one's complement 16-bit checksum
uint16_t compute_checksum(const void *buf, size_t len);

// Verifies whether buffer matches checksum (returns 1 if valid, 0 if corrupt)
int verify_checksum(const void *buf, size_t len);

#endif