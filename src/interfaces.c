#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include "interfaces.h"

router_iface_t g_interfaces[NUM_INTERFACES] = {
    {"eth0", 8001, -1},
    {"eth1", 8002, -1},
    {"eth2", 8003, -1}
};

static void (*g_handler)(int, const char*, void*, int) = NULL;

static void* listener_thread(void *arg) {
    router_iface_t *iface = (router_iface_t *)arg;
    char buffer[2048];
    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);

    while (1) {
        int n = recvfrom(iface->sock_fd, buffer, sizeof(buffer), 0,
                         (struct sockaddr *)&client_addr, &addr_len);
        if (n > 0 && g_handler) {
            g_handler(iface->sock_fd, iface->iface_name, buffer, n);
        }
    }
    return NULL;
}

void interfaces_init(void) {
    for (int i = 0; i < NUM_INTERFACES; i++) {
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) { perror("socket"); exit(1); }

        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(g_interfaces[i].listen_port);
        addr.sin_addr.s_addr = INADDR_ANY;

        if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            perror("bind"); exit(1);
        }
        g_interfaces[i].sock_fd = fd;
        printf("[INIT] %s listening on UDP port %d\n", g_interfaces[i].iface_name, g_interfaces[i].listen_port);
    }
}

void interfaces_start_listeners(void (*handler)(int, const char*, void*, int))
{
    g_handler = handler;

    pthread_t threads[NUM_INTERFACES];

    for (int i = 0; i < NUM_INTERFACES; i++) {
        if (pthread_create(
                &threads[i],
                NULL,
                listener_thread,
                &g_interfaces[i]) != 0) {
            perror("pthread_create");
            exit(1);
        }
    }

    /* Keep the router running */
    for (int i = 0; i < NUM_INTERFACES; i++) {
        pthread_join(threads[i], NULL);
    }
}

void interfaces_close(void) {
    for (int i = 0; i < NUM_INTERFACES; i++) {
        if (g_interfaces[i].sock_fd >= 0) close(g_interfaces[i].sock_fd);
    }
}