#ifndef INTERFACES_H
#define INTERFACES_H

typedef struct {
    char iface_name[16];
    int  listen_port;
    int  sock_fd;
} router_iface_t;

#define NUM_INTERFACES 3

extern router_iface_t g_interfaces[NUM_INTERFACES];

void interfaces_init(void);
void interfaces_start_listeners(void (*packet_handler)(int sock_fd, const char *iface, void *buf, int len));
void interfaces_close(void);

#endif