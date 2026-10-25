#ifndef ROUTER_CORE_H
#define ROUTER_CORE_H

void packet_handler(int sock_fd, const char *iface, void *buf, int len);

void router_start_timer(void);

#endif
