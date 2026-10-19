#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "lpm.h"

static lpm_node_t *trie_root = NULL;

static lpm_node_t* create_node(void) {
    lpm_node_t *node = (lpm_node_t *)calloc(1, sizeof(lpm_node_t));
    if (!node) {
        perror("calloc");
        exit(EXIT_FAILURE);
    }
    return node;
}

void lpm_init(void) {
    if (trie_root) return;
    trie_root = create_node();

    // Default routes setup for subnets
    uint32_t ip_eth0, ip_eth1, ip_gw;
    inet_pton(AF_INET, "192.168.1.0", &ip_eth0);
    inet_pton(AF_INET, "192.168.2.0", &ip_eth1);
    inet_pton(AF_INET, "10.0.0.254", &ip_gw);

    // /24 direct subnets
    lpm_insert(ip_eth0, 24, 0, "eth0", 9001);
    lpm_insert(ip_eth1, 24, 0, "eth1", 9002);

    // /0 Default Gateway
    lpm_insert(0, 0, ip_gw, "eth2", 9003);
}

void lpm_insert(uint32_t network_net_order, uint8_t prefix_len, uint32_t next_hop_net_order, const char *iface, int egress_port) {
    if (!trie_root) trie_root = create_node();

    uint32_t net = ntohl(network_net_order);
    lpm_node_t *curr = trie_root;

    for (int i = 31; i >= (32 - prefix_len); i--) {
        int bit = (net >> i) & 1;
        if (!curr->child[bit]) {
            curr->child[bit] = create_node();
        }
        curr = curr->child[bit];
    }

    curr->is_terminal = 1;
    curr->prefix_len = prefix_len;
    curr->network = network_net_order;
    curr->next_hop = next_hop_net_order;
    strncpy(curr->iface, iface, sizeof(curr->iface) - 1);
    curr->egress_port = egress_port;
}

lpm_node_t* lpm_lookup_fast(uint32_t dest_ip_net_order) {
    if (!trie_root) return NULL;

    uint32_t ip = ntohl(dest_ip_net_order);
    lpm_node_t *curr = trie_root;
    lpm_node_t *best_match = NULL;

    // Traverse trie bit-by-bit
    for (int i = 31; i >= 0; i--) {
        if (!curr) break;
        if (curr->is_terminal) {
            best_match = curr; // Track deepest matching prefix (Longest Match)
        }
        int bit = (ip >> i) & 1;
        curr = curr->child[bit];
    }

    if (curr && curr->is_terminal) {
        best_match = curr;
    }

    return best_match;
}

static void free_subtree(lpm_node_t *node) {
    if (!node) return;
    free_subtree(node->child[0]);
    free_subtree(node->child[1]);
    free(node);
}

void lpm_free(void) {
    free_subtree(trie_root);
    trie_root = NULL;
}