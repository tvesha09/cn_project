#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <time.h>
#include "arp.h"

#define MAX_ARP 32

static arp_entry_t     arp_cache[MAX_ARP];
static int             arp_count = 0;
static pthread_mutex_t arp_lock = PTHREAD_MUTEX_INITIALIZER;

static void arp_expire_locked(time_t now) {
    int write_index = 0;
    for (int i = 0; i < arp_count; i++) {
        if (!arp_cache[i].is_valid) {
            continue;
        }
        if (difftime(now, arp_cache[i].last_seen) >= ARP_CACHE_TTL_SEC) {
            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &arp_cache[i].ip, ip_str, sizeof(ip_str));
            printf("[ARP] Cache entry EXPIRED for IP %s\n", ip_str);
            continue;
        }
        if (write_index != i) {
            arp_cache[write_index] = arp_cache[i];
        }
        write_index++;
    }
    arp_count = write_index;
}

void arp_expire(void) {
    pthread_mutex_lock(&arp_lock);
    arp_expire_locked(time(NULL));
    pthread_mutex_unlock(&arp_lock);
}

void arp_init(void) {
    pthread_mutex_lock(&arp_lock);
    memset(arp_cache, 0, sizeof(arp_cache));
    arp_count = 0;
    pthread_mutex_unlock(&arp_lock);

    printf("[ARP] Dynamic ARP Cache initialized (TTL: %ds)\n", ARP_CACHE_TTL_SEC);
}

void arp_cache_insert(uint32_t ip, const uint8_t *mac, int host_port) {
    time_t now = time(NULL);

    pthread_mutex_lock(&arp_lock);
    arp_expire_locked(now);

    for (int i = 0; i < arp_count; i++) {
        if (arp_cache[i].is_valid && arp_cache[i].ip == ip) {
            memcpy(arp_cache[i].mac, mac, 6);
            arp_cache[i].host_port = host_port;
            arp_cache[i].last_seen = now;
            pthread_mutex_unlock(&arp_lock);

            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &ip, ip_str, sizeof(ip_str));
            printf("[ARP] Cache updated: %s -> %02X:%02X:%02X:%02X:%02X:%02X (Port %d)\n",
                   ip_str, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], host_port);
            return;
        }
    }

    int index = arp_count;
    if (arp_count >= MAX_ARP) {
        index = 0;
        for (int i = 1; i < arp_count; i++) {
            if (arp_cache[i].last_seen < arp_cache[index].last_seen) {
                index = i;
            }
        }
    } else {
        arp_count++;
    }

    arp_cache[index].ip = ip;
    memcpy(arp_cache[index].mac, mac, 6);
    arp_cache[index].host_port = host_port;
    arp_cache[index].last_seen = now;
    arp_cache[index].is_valid = 1;

    pthread_mutex_unlock(&arp_lock);

    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip, ip_str, sizeof(ip_str));
    printf("[ARP] New cache entry added: %s -> %02X:%02X:%02X:%02X:%02X:%02X (Port %d)\n",
           ip_str, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], host_port);
}

void arp_add_entry(uint32_t ip, const uint8_t *mac, int host_port) {
    arp_cache_insert(ip, mac, host_port);
}

void arp_add(const char *ip_str, const uint8_t *mac, int port) {
    if (ip_str == NULL || mac == NULL) {
        return;
    }

    struct in_addr addr;

    if (inet_pton(AF_INET, ip_str, &addr) != 1) {
        addr.s_addr = inet_addr(ip_str);
        if (addr.s_addr == INADDR_NONE) {
            fprintf(stderr, "[ARP] Invalid IP address: %s\n", ip_str);
            return;
        }
    }

    arp_cache_insert(addr.s_addr, mac, port);
}

int arp_cache_lookup(uint32_t ip, uint8_t *out_mac, int *out_port) {
    pthread_mutex_lock(&arp_lock);
    arp_expire_locked(time(NULL));

    for (int i = 0; i < arp_count; i++) {
        if (arp_cache[i].is_valid && arp_cache[i].ip == ip) {
            memcpy(out_mac, arp_cache[i].mac, 6);
            *out_port = arp_cache[i].host_port;
            pthread_mutex_unlock(&arp_lock);
            return 1;
        }
    }

    pthread_mutex_unlock(&arp_lock);
    return 0;
}

int arp_lookup(uint32_t ip, uint8_t *out_mac, int *out_port) {
    return arp_cache_lookup(ip, out_mac, out_port);
}

int arp_parse_message(const void *buf, size_t len, arp_message_t *out) {
    if (buf == NULL || out == NULL || len < sizeof(arp_message_t)) {
        return 0;
    }

    memcpy(out, buf, sizeof(*out));

    if (out->magic != ARP_MAGIC ||
        (out->opcode != ARP_OP_REQUEST && out->opcode != ARP_OP_REPLY)) {
        return 0;
    }

    return 1;
}